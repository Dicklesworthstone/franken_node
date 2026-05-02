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

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use chrono::Utc;
use fs2::FileExt;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn constant_time_eq(a: &str, b: &str) -> bool {
    crate::security::constant_time::ct_eq(a, b)
}

/// RAII guard that orphans a temp file on drop (unless defused after rename).
#[must_use]
struct TempFileGuard(Option<PathBuf>);

impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        Self(Some(path))
    }

    fn abandoned_path(path: &Path) -> PathBuf {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("root-pointer.tmp");
        path.with_file_name(format!("{file_name}.orphaned-{}", Uuid::now_v7()))
    }

    /// Prevent cleanup after a successful rename (file no longer at this path).
    fn defuse(&mut self) {
        self.0 = None;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take()
            && path.is_file()
        {
            let abandoned_path = Self::abandoned_path(&path);
            if let Err(source) = fs::rename(&path, &abandoned_path) {
                tracing::warn!(
                    path = %path.display(),
                    abandoned_path = %abandoned_path.display(),
                    error = %source,
                    "failed to orphan abandoned root pointer temp file"
                );
            }
        }
    }
}

/// RAII guard for the root pointer publication flock.
#[must_use]
struct RootPublicationLockGuard {
    file: File,
    path: PathBuf,
}

impl Drop for RootPublicationLockGuard {
    fn drop(&mut self) {
        if let Err(source) = self.file.unlock() {
            tracing::warn!(
                path = %self.path.display(),
                error = %source,
                "failed to release root publication lock"
            );
        }
    }
}

/// Canonical root pointer filename.
pub const ROOT_POINTER_FILE: &str = "root_pointer.json";
/// Canonical detached auth record filename for root pointer bootstrap checks.
pub const ROOT_POINTER_AUTH_FILE: &str = "root_pointer.auth.json";
/// Stable cross-process publication lock file for root/auth pair snapshots.
pub const ROOT_POINTER_LOCK_FILE: &str = "root_pointer.publish.lock";
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RootPointer {
    pub epoch: ControlEpoch,
    pub marker_stream_head_seq: u64,
    pub marker_stream_head_hash: String,
    pub publication_timestamp: String,
    pub publisher_id: String,
}

impl<'de> Deserialize<'de> for RootPointer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let object = value.as_object().ok_or_else(|| {
            <D::Error as serde::de::Error>::custom("root pointer must be a JSON object")
        })?;

        let epoch = object
            .get("epoch")
            .ok_or_else(|| <D::Error as serde::de::Error>::custom("missing field `epoch`"))?
            .as_u64()
            .ok_or_else(|| {
                <D::Error as serde::de::Error>::custom("field `epoch` must be an unsigned integer")
            })?;
        let marker_stream_head_seq = object
            .get("marker_stream_head_seq")
            .ok_or_else(|| {
                <D::Error as serde::de::Error>::custom("missing field `marker_stream_head_seq`")
            })?
            .as_u64()
            .ok_or_else(|| {
                <D::Error as serde::de::Error>::custom(
                    "field `marker_stream_head_seq` must be an unsigned integer",
                )
            })?;
        let marker_stream_head_hash = object
            .get("marker_stream_head_hash")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                <D::Error as serde::de::Error>::custom(
                    "field `marker_stream_head_hash` must be a string",
                )
            })?
            .to_string();
        let publication_timestamp = object
            .get("publication_timestamp")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                <D::Error as serde::de::Error>::custom(
                    "field `publication_timestamp` must be a string",
                )
            })?
            .to_string();
        let publisher_id = object
            .get("publisher_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                <D::Error as serde::de::Error>::custom("field `publisher_id` must be a string")
            })?
            .to_string();

        Ok(Self {
            epoch: ControlEpoch(epoch),
            marker_stream_head_seq,
            marker_stream_head_hash,
            publication_timestamp,
            publisher_id,
        })
    }
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
    #[error("publish mutex poisoned")]
    LockPoisoned,
    #[error("invalid signing key during {context}: {reason}")]
    SigningKeyInvalid {
        context: &'static str,
        reason: String,
    },
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
            Self::LockPoisoned => "ROOT_LOCK_POISONED",
            Self::SigningKeyInvalid { .. } => "ROOT_SIGNING_KEY_INVALID",
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct PublishOptions {
    crash_after: Option<PublishStep>,
    delay_after_lock: Option<Duration>,
}

fn publish_lock_registry() -> &'static Mutex<BTreeMap<PathBuf, Arc<Mutex<()>>>> {
    static LOCKS: OnceLock<Mutex<BTreeMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();
    LOCKS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn publish_lock(dir: &Path) -> Result<Arc<Mutex<()>>, RootPointerError> {
    let lock_path = root_publication_lock_path(dir);
    let lock_key = lock_path.canonicalize().unwrap_or(lock_path);
    let mut registry = publish_lock_registry()
        .lock()
        .map_err(|_| RootPointerError::LockPoisoned)?;
    Ok(Arc::clone(
        registry
            .entry(lock_key)
            .or_insert_with(|| Arc::new(Mutex::new(()))),
    ))
}

/// Compute stable cross-process publication lock path for a root directory.
#[must_use]
fn root_publication_lock_path(dir: &Path) -> PathBuf {
    dir.join(ROOT_POINTER_LOCK_FILE)
}

fn acquire_root_publication_lock(
    dir: &Path,
    shared: bool,
) -> Result<RootPublicationLockGuard, RootPointerError> {
    let path = root_publication_lock_path(dir);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|source| RootPointerError::Io {
            step: "open_publication_lock",
            path: path.display().to_string(),
            source,
        })?;
    let lock_result = if shared {
        file.lock_shared()
    } else {
        file.lock()
    };
    lock_result.map_err(|source| RootPointerError::Io {
        step: if shared {
            "lock_publication_shared"
        } else {
            "lock_publication_exclusive"
        },
        path: path.display().to_string(),
        source,
    })?;
    Ok(RootPublicationLockGuard { file, path })
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

fn read_root_bytes(path: &Path) -> Result<Vec<u8>, RootPointerError> {
    fs::read(path).map_err(|source| {
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
    })
}

fn read_root_unlocked(dir: &Path) -> Result<RootPointer, RootPointerError> {
    let path = root_pointer_path(dir);
    let bytes = read_root_bytes(&path)?;
    serde_json::from_slice::<RootPointer>(&bytes).map_err(|source| RootPointerError::Deserialize {
        path: path.display().to_string(),
        source,
    })
}

/// Read and deserialize the canonical root pointer under the publication lock.
pub fn read_root(dir: &Path) -> Result<RootPointer, RootPointerError> {
    let _publication_lock = acquire_root_publication_lock(dir, true)?;
    read_root_unlocked(dir)
}

/// Fail-closed bootstrap gate for root pointer authentication + epoch/version checks.
///
/// No caller should treat root state as trusted until this function succeeds.
pub fn bootstrap_root(
    dir: &Path,
    auth_config: &RootAuthConfig,
) -> Result<VerifiedRoot, BootstrapError> {
    let _publication_lock = acquire_root_publication_lock(dir, true).map_err(|source| {
        BootstrapError::RootAuthFailed {
            reason: format!("unable to acquire root publication lock: {source}"),
        }
    })?;
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
    if root.epoch < auth_config.current_epoch || root.epoch > max_allowed_epoch {
        return Err(BootstrapError::RootEpochInvalid {
            current_epoch: auth_config.current_epoch,
            root_epoch: root.epoch,
            max_allowed_epoch,
        });
    }

    let root_hash = hash_hex(&root_bytes);
    if !constant_time_eq(&auth.root_hash, &root_hash) {
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

    let expected_mac = sign_payload(&root_hash, &auth_config.trust_anchor).map_err(|source| {
        BootstrapError::RootAuthFailed {
            reason: format!("detached root MAC verification setup failed: {source}"),
        }
    })?;
    if !constant_time_eq(&auth.mac, &expected_mac) {
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
    let expected = sign_payload(&canonical, signing_key).map_err(|source| {
        RootPointerError::SigningKeyInvalid {
            context: "verify_publish_event",
            reason: source.to_string(),
        }
    })?;
    Ok(constant_time_eq(&expected, &event.signature))
}

fn publish_root_internal(
    dir: &Path,
    root: &RootPointer,
    signing_key: &[u8],
    trace_id: &str,
    options: PublishOptions,
) -> Result<RootPublishOutcome, RootPointerError> {
    let _publication_lock = acquire_root_publication_lock(dir, false)?;
    let publication_mutex = publish_lock(dir)?;
    let _guard = publication_mutex
        .lock()
        .map_err(|_| RootPointerError::LockPoisoned)?;
    if let Some(delay) = options.delay_after_lock {
        thread::sleep(delay);
    }

    let start = Instant::now();
    let root_path = root_pointer_path(dir);
    let temp_path = dir.join(format!(".{}.tmp.{}", ROOT_POINTER_FILE, Uuid::now_v7()));
    let mut _temp_guard = TempFileGuard::new(temp_path.clone());
    let old_root = match read_root_unlocked(dir) {
        Ok(r) => {
            // Verify MAC of existing root before trusting its epoch
            let auth_path = root_auth_path(dir);
            let auth_bytes = match fs::read(&auth_path) {
                Ok(b) => b,
                Err(_) => {
                    return Err(RootPointerError::SigningKeyInvalid {
                        context: "verify_old_root_auth",
                        reason: "existing root pointer found but auth record is missing"
                            .to_string(),
                    });
                }
            };
            let auth: RootAuthRecord = match serde_json::from_slice(&auth_bytes) {
                Ok(a) => a,
                Err(e) => {
                    return Err(RootPointerError::Deserialize {
                        path: auth_path.display().to_string(),
                        source: e,
                    });
                }
            };

            let root_bytes = read_root_bytes(&root_path)?;
            let root_hash = hash_hex(&root_bytes);

            let expected_mac = sign_payload(&root_hash, signing_key).map_err(|source| {
                RootPointerError::SigningKeyInvalid {
                    context: "verify_old_root_auth",
                    reason: source.to_string(),
                }
            })?;

            if !constant_time_eq(&auth.mac, &expected_mac)
                || !constant_time_eq(&auth.root_hash, &root_hash)
                || auth.epoch != r.epoch
            {
                return Err(RootPointerError::SigningKeyInvalid {
                    context: "verify_old_root_auth",
                    reason: "existing root pointer is tampered or invalid; epoch regression check cannot proceed safely".to_string(),
                });
            }
            Some(r)
        }
        Err(RootPointerError::MissingRoot { .. }) => None,
        Err(e) => return Err(e),
    };

    if let Some(previous) = &old_root
        && root.epoch <= previous.epoch
    {
        return Err(RootPointerError::EpochRegression {
            attempted: root.epoch,
            current: previous.epoch,
        });
    }

    let payload = serde_json::to_vec_pretty(root).map_err(RootPointerError::Serialize)?;

    let manifest_hash = hash_hex(&payload);
    let auth_record = RootAuthRecord {
        root_format_version: ROOT_POINTER_FORMAT_VERSION.to_string(),
        root_hash: manifest_hash.clone(),
        epoch: root.epoch,
        issued_at: Utc::now().to_rfc3339(),
        mac: sign_payload(&manifest_hash, signing_key).map_err(|source| {
            RootPointerError::SigningKeyInvalid {
                context: "publish_root_auth",
                reason: source.to_string(),
            }
        })?,
    };
    let auth_payload =
        serde_json::to_vec_pretty(&auth_record).map_err(RootPointerError::Serialize)?;

    let mut trace = PublishTrace::default();

    let temp_auth_path = dir.join(format!(
        ".{}.tmp.{}",
        ROOT_POINTER_AUTH_FILE,
        Uuid::now_v7()
    ));
    let mut _temp_auth_guard = TempFileGuard::new(temp_auth_path.clone());
    let auth_path = root_auth_path(dir);

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

    let mut temp_auth_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_auth_path)
        .map_err(|source| RootPointerError::Io {
            step: "write_root_auth_temp",
            path: temp_auth_path.display().to_string(),
            source,
        })?;
    temp_auth_file
        .write_all(&auth_payload)
        .map_err(|source| RootPointerError::Io {
            step: "write_root_auth_temp",
            path: temp_auth_path.display().to_string(),
            source,
        })?;
    temp_auth_file
        .flush()
        .map_err(|source| RootPointerError::Io {
            step: "write_root_auth_temp",
            path: temp_auth_path.display().to_string(),
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
    temp_auth_file
        .sync_all()
        .map_err(|source| RootPointerError::Io {
            step: "fsync_root_auth_temp",
            path: temp_auth_path.display().to_string(),
            source,
        })?;

    trace.steps.push(PublishStep::FsyncTemp);
    maybe_crash(options.crash_after, PublishStep::FsyncTemp)?;

    fs::rename(&temp_path, &root_path).map_err(|source| RootPointerError::Io {
        step: "rename",
        path: root_path.display().to_string(),
        source,
    })?;
    _temp_guard.defuse(); // temp file no longer exists at original path
    fs::rename(&temp_auth_path, &auth_path).map_err(|source| RootPointerError::Io {
        step: "rename_root_auth",
        path: auth_path.display().to_string(),
        source,
    })?;
    _temp_auth_guard.defuse();

    trace.steps.push(PublishStep::Rename);
    maybe_crash(options.crash_after, PublishStep::Rename)?;

    sync_directory(dir)?;
    trace.steps.push(PublishStep::FsyncDir);
    maybe_crash(options.crash_after, PublishStep::FsyncDir)?;

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
    let signature = sign_payload(&signature_payload, signing_key).map_err(|source| {
        RootPointerError::SigningKeyInvalid {
            context: "publish_root_event",
            reason: source.to_string(),
        }
    })?;

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
    hasher.update(b"root_pointer_hash_v1:");
    let payload_len = u64::try_from(payload.len()).unwrap_or(u64::MAX);
    hasher.update(payload_len.to_le_bytes());
    hasher.update(payload);
    hex::encode(hasher.finalize())
}

fn sign_payload(payload: &str, signing_key: &[u8]) -> Result<String, hmac::digest::InvalidLength> {
    let mut mac = Hmac::<Sha256>::new_from_slice(signing_key)?;
    mac.update(b"root_pointer_sign_v1:");
    let payload_len = u64::try_from(payload.len()).unwrap_or(u64::MAX);
    mac.update(&payload_len.to_le_bytes());
    mac.update(payload.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
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
    use super::{
        BootstrapError, ControlEpoch, Digest, Hmac, KeyInit, Mac, OpenOptions, PublishStep,
        ROOT_POINTER_FORMAT_VERSION, ROOT_PUBLISH_COMPLETE, ROOT_PUBLISH_START, RootAuthConfig,
        RootAuthRecord, RootPointer, RootPointerError, Sha256, TempFileGuard, Utc, bootstrap_root,
        fs, hash_hex, publish_lock, publish_root, publish_root_with_crash_injection,
        publish_root_with_delay_for_test, read_root, root_auth_path, root_pointer_path,
        root_publication_lock_path, sign_payload, thread, verify_publish_event,
    };
    use std::time::{Duration, Instant};
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

    fn tamper_same_length(input: &str) -> String {
        let mut chars: Vec<char> = input.chars().collect();
        let idx = chars
            .iter()
            .position(|ch| *ch != '0')
            .unwrap_or(chars.len().saturating_sub(1));
        chars[idx] = if chars[idx] == '0' { '1' } else { '0' };
        chars.into_iter().collect()
    }

    #[test]
    fn root_pointer_hash_and_mac_length_prefix_payloads() {
        let payload = b"root-pointer";
        let mut expected_hash = Sha256::new();
        expected_hash.update(b"root_pointer_hash_v1:");
        let payload_len = u64::try_from(payload.len()).unwrap_or(u64::MAX);
        expected_hash.update(payload_len.to_le_bytes());
        expected_hash.update(payload);

        assert_eq!(hash_hex(payload), hex::encode(expected_hash.finalize()));

        let signing_key = key();
        let mac_payload = "root-pointer-mac";
        let mut expected_mac = Hmac::<Sha256>::new_from_slice(&signing_key).expect("hmac key");
        expected_mac.update(b"root_pointer_sign_v1:");
        let mac_payload_len = u64::try_from(mac_payload.len()).unwrap_or(u64::MAX);
        expected_mac.update(&mac_payload_len.to_le_bytes());
        expected_mac.update(mac_payload.as_bytes());

        assert_eq!(
            sign_payload(mac_payload, &signing_key).expect("sign"),
            hex::encode(expected_mac.finalize().into_bytes())
        );
    }

    #[test]
    fn temp_file_guard_orphans_abandoned_temp_files() {
        let dir = TempDir::new().expect("tempdir");
        let temp_path = dir.path().join("root_pointer.json.tmp");
        fs::write(&temp_path, "pending").expect("write temp");

        {
            let _guard = TempFileGuard::new(temp_path.clone());
        }

        assert!(!temp_path.exists(), "temp file should be moved aside");
        let orphaned = fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("root_pointer.json.tmp.orphaned-"))
            })
            .collect::<Vec<_>>();
        assert_eq!(orphaned.len(), 1, "expected one orphaned temp artifact");
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
    fn read_root_missing_returns_missing_root_error() {
        let dir = TempDir::new().expect("tempdir");
        let err = read_root(dir.path()).expect_err("missing root should fail");
        assert!(matches!(err, RootPointerError::MissingRoot { .. }));
        assert_eq!(err.code(), "ROOT_NOT_FOUND");
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
                Duration::from_millis(1000),
            )
            .expect("thread-1 publish")
        });

        // Give thread-1 enough time to spawn and acquire the lock.
        // 120ms was too tight and caused flaky failures on loaded machines.
        thread::sleep(Duration::from_millis(500));

        let start = Instant::now();
        let t2_outcome =
            publish_root(dir.path(), &root(3, 3, "h3"), &k, "thread-2").expect("thread-2 publish");
        let elapsed = start.elapsed();

        let _ = t1.join().expect("thread-1 join");
        assert!(
            elapsed >= Duration::from_millis(400),
            "second publish should wait behind first (elapsed: {elapsed:?})"
        );
        assert_eq!(t2_outcome.event.event_code, ROOT_PUBLISH_COMPLETE);
    }

    #[test]
    fn publish_waits_for_cross_process_publication_lock() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();

        publish_root(dir.path(), &root(1, 1, "h1"), &k, "seed").expect("seed publish");

        let lock_path = root_publication_lock_path(dir.path());
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .expect("open publication lock");
        lock_file.lock().expect("take external publication lock");

        let dir_path = dir.path().to_path_buf();
        let key_for_thread = k.clone();
        let publisher = thread::spawn(move || {
            publish_root(
                &dir_path,
                &root(2, 2, "h2"),
                &key_for_thread,
                "external-lock",
            )
        });

        thread::sleep(Duration::from_millis(100));
        assert!(
            !publisher.is_finished(),
            "publisher must wait behind externally-held publication lock"
        );

        lock_file
            .unlock()
            .expect("release external publication lock");
        let outcome = publisher
            .join()
            .expect("publisher join")
            .expect("publish after external lock release");
        assert_eq!(outcome.event.new_epoch, ControlEpoch(2));
    }

    #[test]
    fn publish_waiting_on_publication_flock_does_not_hold_process_mutex() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();

        publish_root(dir.path(), &root(1, 1, "h1"), &k, "seed").expect("seed publish");

        let lock_path = root_publication_lock_path(dir.path());
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .expect("open publication lock");
        lock_file.lock().expect("take external publication lock");

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let dir_path = dir.path().to_path_buf();
        let key_for_thread = k.clone();
        let publisher = thread::spawn(move || {
            started_tx.send(()).expect("signal publisher started");
            publish_root(
                &dir_path,
                &root(2, 2, "h2"),
                &key_for_thread,
                "external-lock-order",
            )
        });

        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("publisher must start");
        thread::sleep(Duration::from_millis(100));
        let publication_mutex = publish_lock(dir.path()).expect("directory-scoped process mutex");
        let process_guard = publication_mutex
            .try_lock()
            .expect("publisher blocked on flock must not hold process mutex");
        drop(process_guard);

        lock_file
            .unlock()
            .expect("release external publication lock");
        let outcome = publisher
            .join()
            .expect("publisher join")
            .expect("publish after external lock release");
        assert_eq!(outcome.event.new_epoch, ControlEpoch(2));
    }

    #[test]
    fn publish_in_other_directory_does_not_wait_for_unrelated_process_mutex() {
        let dir_a = TempDir::new().expect("tempdir a");
        let dir_b = TempDir::new().expect("tempdir b");
        let k = key();

        publish_root(dir_a.path(), &root(1, 1, "h1"), &k, "seed-a").expect("seed publish a");
        publish_root(dir_b.path(), &root(1, 1, "h1"), &k, "seed-b").expect("seed publish b");

        let dir_a_process_lock =
            publish_lock(dir_a.path()).expect("directory-scoped process mutex for dir a");
        let held_guard = dir_a_process_lock
            .lock()
            .expect("hold directory-scoped process mutex");

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let dir_a_path = dir_a.path().to_path_buf();
        let key_for_thread = k.clone();
        let publisher_a = thread::spawn(move || {
            started_tx.send(()).expect("signal publisher a started");
            publish_root(&dir_a_path, &root(2, 2, "h2-a"), &key_for_thread, "dir-a")
        });

        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("publisher a must start");
        thread::sleep(Duration::from_millis(100));
        assert!(
            !publisher_a.is_finished(),
            "dir_a publisher must still be waiting on the held dir_a process mutex"
        );

        let start = Instant::now();
        let outcome_b =
            publish_root(dir_b.path(), &root(2, 2, "h2-b"), &k, "dir-b").expect("dir_b publish");
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_millis(400),
            "dir_b publish must not wait behind dir_a process mutex (elapsed: {elapsed:?})"
        );
        assert_eq!(outcome_b.event.new_epoch, ControlEpoch(2));

        drop(held_guard);
        let outcome_a = publisher_a
            .join()
            .expect("publisher a join")
            .expect("dir_a publish after releasing dir_a process mutex");
        assert_eq!(outcome_a.event.new_epoch, ControlEpoch(2));
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
        assert_eq!(
            verified.auth.root_format_version,
            ROOT_POINTER_FORMAT_VERSION
        );
    }

    #[test]
    fn bootstrap_waits_for_publication_lock_before_reading_root_auth_pair() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();

        publish_root(dir.path(), &root(1, 1, "seed"), &k, "seed").expect("seed publish");

        let lock_path = root_publication_lock_path(dir.path());
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .expect("open publication lock");
        lock_file.lock().expect("take publication lock");

        let next = root(2, 2, "next");
        let payload = serde_json::to_vec_pretty(&next).expect("serialize next root");
        fs::write(root_pointer_path(dir.path()), &payload).expect("write torn root");

        let cfg = RootAuthConfig::strict(k.clone(), ControlEpoch(2));
        let dir_path = dir.path().to_path_buf();
        let bootstrapper = thread::spawn(move || bootstrap_root(&dir_path, &cfg));

        let wait_started = Instant::now();
        while wait_started.elapsed() < Duration::from_millis(120) {
            assert!(
                !bootstrapper.is_finished(),
                "bootstrap must wait behind publication lock instead of reading a torn pair"
            );
            thread::sleep(Duration::from_millis(10));
        }

        let root_hash = hash_hex(&payload);
        let auth_record = RootAuthRecord {
            root_format_version: ROOT_POINTER_FORMAT_VERSION.to_string(),
            root_hash: root_hash.clone(),
            epoch: next.epoch,
            issued_at: Utc::now().to_rfc3339(),
            mac: sign_payload(&root_hash, &k).expect("sign auth"),
        };
        fs::write(
            root_auth_path(dir.path()),
            serde_json::to_vec_pretty(&auth_record).expect("serialize auth"),
        )
        .expect("write matching auth");
        lock_file.unlock().expect("release publication lock");

        let verified = bootstrapper
            .join()
            .expect("bootstrap join")
            .expect("bootstrap after matching auth publish");
        assert_eq!(verified.root, next);
        assert_eq!(verified.auth.root_hash, root_hash);
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
    fn bootstrap_rejects_same_length_tampered_root_hash() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        let root = root(3, 30, "hash-3");
        publish_root(dir.path(), &root, &k, "trace-bootstrap-root-hash").expect("publish");

        let auth_path = root_auth_path(dir.path());
        let mut auth: RootAuthRecord = serde_json::from_slice(&fs::read(&auth_path).expect("read"))
            .expect("parse auth record");
        assert!(!auth.root_hash.is_empty(), "root hash should not be empty");
        auth.root_hash = tamper_same_length(&auth.root_hash);
        fs::write(
            &auth_path,
            serde_json::to_vec_pretty(&auth).expect("serialize tampered auth"),
        )
        .expect("write tampered auth");

        let cfg = RootAuthConfig::strict(k, ControlEpoch(3));
        let err = bootstrap_root(dir.path(), &cfg).expect_err("tampered root hash should fail");
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
    fn bootstrap_rejects_stale_epoch_root() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        let root = root(5, 90, "hash-5");
        publish_root(dir.path(), &root, &k, "trace-bootstrap-stale-epoch").expect("publish");

        let cfg = RootAuthConfig {
            trust_anchor: k,
            expected_format_version: ROOT_POINTER_FORMAT_VERSION.to_string(),
            current_epoch: ControlEpoch(7),
            max_future_epochs: 1,
        };

        let err = bootstrap_root(dir.path(), &cfg).expect_err("stale epoch must fail");
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

    #[test]
    fn epoch_regression_check_validates_existing_mac() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();

        // 1. Publish a legitimate high-epoch root (epoch 1000)
        let root_1000 = root(1000, 10, "hash1000");
        publish_root(dir.path(), &root_1000, &k, "trace-1").expect("seed");

        // 2. Attacker modifies the root_pointer.json on disk to epoch 0, bypassing MAC
        let mut tampered_root = root_1000.clone();
        tampered_root.epoch = ControlEpoch(0);
        fs::write(
            root_pointer_path(dir.path()),
            serde_json::to_vec_pretty(&tampered_root).unwrap(),
        )
        .unwrap();

        // 3. The node attempts to publish a new root with epoch 1 (which SHOULD be a regression from 1000)
        let root_1 = root(1, 11, "hash1");

        let err = publish_root(dir.path(), &root_1, &k, "trace-2")
            .expect_err("tampered root should fail publication check");

        assert_eq!(err.code(), "ROOT_SIGNING_KEY_INVALID");
    }

    #[test]
    fn read_root_malformed_payload_returns_deserialize_error() {
        let dir = TempDir::new().expect("tempdir");
        fs::write(root_pointer_path(dir.path()), b"{not valid root json").expect("write root");

        let err = read_root(dir.path()).expect_err("malformed root must fail");

        assert!(matches!(err, RootPointerError::Deserialize { .. }));
        assert_eq!(err.code(), "ROOT_DESERIALIZE_FAILED");
    }

    #[test]
    fn bootstrap_rejects_missing_auth_record() {
        let dir = TempDir::new().expect("tempdir");
        let root = root(10, 100, "missing-auth");
        fs::write(
            root_pointer_path(dir.path()),
            serde_json::to_vec_pretty(&root).expect("serialize root"),
        )
        .expect("write root");

        let cfg = RootAuthConfig::strict(key(), ControlEpoch(10));
        let err = bootstrap_root(dir.path(), &cfg).expect_err("missing auth must fail");

        assert_eq!(err.code(), "ROOT_BOOTSTRAP_AUTH_FAILED");
        assert!(err.to_string().contains("unable to read auth record"));
    }

    #[test]
    fn bootstrap_rejects_malformed_auth_record() {
        let dir = TempDir::new().expect("tempdir");
        let root = root(10, 100, "bad-auth");
        fs::write(
            root_pointer_path(dir.path()),
            serde_json::to_vec_pretty(&root).expect("serialize root"),
        )
        .expect("write root");
        fs::write(root_auth_path(dir.path()), b"{not auth json").expect("write auth");

        let cfg = RootAuthConfig::strict(key(), ControlEpoch(10));
        let err = bootstrap_root(dir.path(), &cfg).expect_err("malformed auth must fail");

        assert_eq!(err.code(), "ROOT_BOOTSTRAP_AUTH_FAILED");
        assert!(err.to_string().contains("unable to parse auth record"));
    }

    #[test]
    fn bootstrap_rejects_auth_epoch_mismatch() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        let root = root(11, 110, "epoch-mismatch");
        publish_root(dir.path(), &root, &k, "trace-auth-epoch").expect("publish");

        let auth_path = root_auth_path(dir.path());
        let mut auth: RootAuthRecord = serde_json::from_slice(&fs::read(&auth_path).expect("read"))
            .expect("parse auth record");
        auth.epoch = ControlEpoch(12);
        fs::write(
            &auth_path,
            serde_json::to_vec_pretty(&auth).expect("serialize auth"),
        )
        .expect("write auth");

        let cfg = RootAuthConfig::strict(k, ControlEpoch(11));
        let err = bootstrap_root(dir.path(), &cfg).expect_err("auth epoch mismatch must fail");

        assert_eq!(err.code(), "ROOT_BOOTSTRAP_AUTH_FAILED");
        assert!(err.to_string().contains("epoch mismatch"));
    }

    #[test]
    fn bootstrap_rejects_wrong_trust_anchor() {
        let dir = TempDir::new().expect("tempdir");
        let root = root(12, 120, "wrong-anchor");
        publish_root(dir.path(), &root, &key(), "trace-wrong-anchor").expect("publish");

        let cfg = RootAuthConfig::strict(b"different-bootstrap-anchor".to_vec(), ControlEpoch(12));
        let err = bootstrap_root(dir.path(), &cfg).expect_err("wrong anchor must fail");

        assert_eq!(err.code(), "ROOT_BOOTSTRAP_AUTH_FAILED");
        assert!(err.to_string().contains("MAC verification failed"));
    }

    #[test]
    fn publish_rejects_existing_root_without_auth_record() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        publish_root(dir.path(), &root(20, 200, "seed"), &k, "trace-seed").expect("publish");
        fs::remove_file(root_auth_path(dir.path())).expect("remove auth");

        let err = publish_root(dir.path(), &root(21, 210, "next"), &k, "trace-next")
            .expect_err("missing auth must block publication");

        assert_eq!(err.code(), "ROOT_SIGNING_KEY_INVALID");
        assert!(err.to_string().contains("auth record is missing"));
    }

    #[test]
    fn publish_rejects_existing_root_with_malformed_auth_record() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        publish_root(dir.path(), &root(30, 300, "seed"), &k, "trace-seed").expect("publish");
        fs::write(root_auth_path(dir.path()), b"{broken auth").expect("write broken auth");

        let err = publish_root(dir.path(), &root(31, 310, "next"), &k, "trace-next")
            .expect_err("malformed auth must block publication");

        assert_eq!(err.code(), "ROOT_DESERIALIZE_FAILED");
    }

    #[test]
    fn serde_rejects_root_pointer_missing_publisher() {
        let json = serde_json::json!({
            "epoch": 1,
            "marker_stream_head_seq": 10,
            "marker_stream_head_hash": "head",
            "publication_timestamp": Utc::now().to_rfc3339()
        });

        let err = serde_json::from_value::<RootPointer>(json)
            .expect_err("missing publisher must fail deserialization");

        assert!(err.to_string().contains("publisher_id"));
    }

    #[test]
    fn verify_publish_event_rejects_empty_signature() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        let mut event = publish_root(dir.path(), &root(40, 400, "sig-empty"), &k, "trace-sig")
            .expect("publish")
            .event;
        event.signature.clear();

        let verified = verify_publish_event(&event, &k).expect("verification should run");

        assert!(!verified);
    }

    #[test]
    fn verify_publish_event_rejects_wrong_signing_key() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        let event = publish_root(
            dir.path(),
            &root(41, 410, "wrong-key"),
            &k,
            "trace-wrong-key",
        )
        .expect("publish")
        .event;

        let verified = verify_publish_event(&event, b"wrong-publication-key")
            .expect("verification should run");

        assert!(!verified);
    }

    #[test]
    fn verify_publish_event_rejects_tampered_trace_id() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        let mut event = publish_root(dir.path(), &root(42, 420, "trace"), &k, "trace-original")
            .expect("publish")
            .event;
        event.trace_id = "trace-tampered".to_string();

        let verified = verify_publish_event(&event, &k).expect("verification should run");

        assert!(!verified);
    }

    #[test]
    fn verify_publish_event_rejects_tampered_epoch() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        let mut event = publish_root(dir.path(), &root(43, 430, "epoch"), &k, "trace-epoch")
            .expect("publish")
            .event;
        event.new_epoch = ControlEpoch(44);

        let verified = verify_publish_event(&event, &k).expect("verification should run");

        assert!(!verified);
    }

    #[test]
    fn bootstrap_rejects_empty_auth_root_hash() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        let root = root(50, 500, "empty-root-hash");
        publish_root(dir.path(), &root, &k, "trace-empty-root-hash").expect("publish");

        let auth_path = root_auth_path(dir.path());
        let mut auth: RootAuthRecord = serde_json::from_slice(&fs::read(&auth_path).expect("read"))
            .expect("parse auth record");
        auth.root_hash.clear();
        fs::write(
            &auth_path,
            serde_json::to_vec_pretty(&auth).expect("serialize auth"),
        )
        .expect("write auth");

        let cfg = RootAuthConfig::strict(k, ControlEpoch(50));
        let err = bootstrap_root(dir.path(), &cfg).expect_err("empty root hash must fail");

        assert_eq!(err.code(), "ROOT_BOOTSTRAP_AUTH_FAILED");
        assert!(err.to_string().contains("root hash mismatch"));
    }

    #[test]
    fn bootstrap_rejects_empty_auth_mac() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        let root = root(51, 510, "empty-mac");
        publish_root(dir.path(), &root, &k, "trace-empty-mac").expect("publish");

        let auth_path = root_auth_path(dir.path());
        let mut auth: RootAuthRecord = serde_json::from_slice(&fs::read(&auth_path).expect("read"))
            .expect("parse auth record");
        auth.mac.clear();
        fs::write(
            &auth_path,
            serde_json::to_vec_pretty(&auth).expect("serialize auth"),
        )
        .expect("write auth");

        let cfg = RootAuthConfig::strict(k, ControlEpoch(51));
        let err = bootstrap_root(dir.path(), &cfg).expect_err("empty MAC must fail");

        assert_eq!(err.code(), "ROOT_BOOTSTRAP_AUTH_FAILED");
        assert!(err.to_string().contains("MAC verification failed"));
    }

    #[test]
    fn bootstrap_rejects_padded_auth_root_hash() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        let root = root(52, 520, "padded-root-hash");
        publish_root(dir.path(), &root, &k, "trace-padded-root-hash").expect("publish");

        let auth_path = root_auth_path(dir.path());
        let mut auth: RootAuthRecord = serde_json::from_slice(&fs::read(&auth_path).expect("read"))
            .expect("parse auth record");
        auth.root_hash = format!(" {} ", auth.root_hash);
        fs::write(
            &auth_path,
            serde_json::to_vec_pretty(&auth).expect("serialize auth"),
        )
        .expect("write auth");

        let cfg = RootAuthConfig::strict(k, ControlEpoch(52));
        let err = bootstrap_root(dir.path(), &cfg).expect_err("padded root hash must fail");

        assert_eq!(err.code(), "ROOT_BOOTSTRAP_AUTH_FAILED");
        assert!(err.to_string().contains("root hash mismatch"));
    }

    #[test]
    fn bootstrap_rejects_padded_auth_mac() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        let root = root(53, 530, "padded-mac");
        publish_root(dir.path(), &root, &k, "trace-padded-mac").expect("publish");

        let auth_path = root_auth_path(dir.path());
        let mut auth: RootAuthRecord = serde_json::from_slice(&fs::read(&auth_path).expect("read"))
            .expect("parse auth record");
        auth.mac = format!("{} ", auth.mac);
        fs::write(
            &auth_path,
            serde_json::to_vec_pretty(&auth).expect("serialize auth"),
        )
        .expect("write auth");

        let cfg = RootAuthConfig::strict(k, ControlEpoch(53));
        let err = bootstrap_root(dir.path(), &cfg).expect_err("padded MAC must fail");

        assert_eq!(err.code(), "ROOT_BOOTSTRAP_AUTH_FAILED");
        assert!(err.to_string().contains("MAC verification failed"));
    }

    #[test]
    fn bootstrap_rejects_auth_hash_for_different_root_even_with_valid_mac() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        let real_root = root(54, 540, "real-root");
        publish_root(dir.path(), &real_root, &k, "trace-real-root").expect("publish");

        let other_root = root(54, 541, "other-root");
        let other_payload = serde_json::to_vec_pretty(&other_root).expect("serialize other root");
        let other_hash = hash_hex(&other_payload);

        let auth_path = root_auth_path(dir.path());
        let mut auth: RootAuthRecord = serde_json::from_slice(&fs::read(&auth_path).expect("read"))
            .expect("parse auth record");
        auth.root_hash = other_hash;
        auth.mac = sign_payload(&auth.root_hash, &k).expect("sign tampered root hash");
        fs::write(
            &auth_path,
            serde_json::to_vec_pretty(&auth).expect("serialize auth"),
        )
        .expect("write auth");

        let cfg = RootAuthConfig::strict(k, ControlEpoch(54));
        let err = bootstrap_root(dir.path(), &cfg).expect_err("wrong root hash must fail");

        assert_eq!(err.code(), "ROOT_BOOTSTRAP_AUTH_FAILED");
        assert!(err.to_string().contains("root hash mismatch"));
    }

    #[test]
    fn bootstrap_rejects_empty_auth_format_version() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        let root = root(55, 550, "empty-format");
        publish_root(dir.path(), &root, &k, "trace-empty-format").expect("publish");

        let auth_path = root_auth_path(dir.path());
        let mut auth: RootAuthRecord = serde_json::from_slice(&fs::read(&auth_path).expect("read"))
            .expect("parse auth record");
        auth.root_format_version.clear();
        fs::write(
            &auth_path,
            serde_json::to_vec_pretty(&auth).expect("serialize auth"),
        )
        .expect("write auth");

        let cfg = RootAuthConfig::strict(k, ControlEpoch(55));
        let err = bootstrap_root(dir.path(), &cfg).expect_err("empty version must fail");

        assert_eq!(err.code(), "ROOT_BOOTSTRAP_VERSION_MISMATCH");
    }

    #[test]
    fn serde_rejects_root_pointer_string_epoch() {
        let json = serde_json::json!({
            "epoch": "56",
            "marker_stream_head_seq": 560,
            "marker_stream_head_hash": "string-epoch",
            "publication_timestamp": Utc::now().to_rfc3339(),
            "publisher_id": "test-publisher",
        });

        let err = serde_json::from_value::<RootPointer>(json)
            .expect_err("string epoch must fail deserialization");

        assert!(err.to_string().contains("epoch"));
    }

    #[test]
    fn serde_rejects_root_pointer_negative_marker_sequence() {
        let json = serde_json::json!({
            "epoch": 57,
            "marker_stream_head_seq": -1,
            "marker_stream_head_hash": "negative-seq",
            "publication_timestamp": Utc::now().to_rfc3339(),
            "publisher_id": "test-publisher",
        });

        let err = serde_json::from_value::<RootPointer>(json)
            .expect_err("negative marker sequence must fail deserialization");

        assert!(err.to_string().contains("marker_stream_head_seq"));
    }

    #[test]
    fn verify_publish_event_rejects_tampered_event_code() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        let mut event = publish_root(dir.path(), &root(58, 580, "event-code"), &k, "trace-event")
            .expect("publish")
            .event;
        event.event_code = ROOT_PUBLISH_START.to_string();

        let verified = verify_publish_event(&event, &k).expect("verification should run");

        assert!(!verified);
    }

    #[test]
    fn test_publish_unicode_injection_in_trace_id() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        let root = root(100, 1000, "unicode-trace-test");

        let malicious_trace = "normal\u{202e}evil\u{202c}trace";
        let outcome =
            publish_root(dir.path(), &root, &k, malicious_trace).expect("publish unicode trace");

        assert_eq!(outcome.event.trace_id, malicious_trace);
        assert!(verify_publish_event(&outcome.event, &k).expect("verify"));
    }

    #[test]
    fn test_bootstrap_massive_root_hash_memory_stress() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        let mut root = root(101, 1010, "massive-hash");

        root.marker_stream_head_hash = "c".repeat(10 * 1024 * 1024);

        let result = publish_root(dir.path(), &root, &k, "massive-hash-test");
        assert!(result.is_ok());

        let cfg = RootAuthConfig::strict(k, ControlEpoch(101));
        let bootstrap_result = bootstrap_root(dir.path(), &cfg);

        assert!(bootstrap_result.is_ok());
        let bootstrapped = bootstrap_result.unwrap();
        assert_eq!(
            bootstrapped.root.marker_stream_head_hash.len(),
            10 * 1024 * 1024
        );
    }

    #[test]
    fn test_publish_epoch_arithmetic_overflow_boundaries() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();

        let root_max = root(u64::MAX, u64::MAX.saturating_sub(1), "epoch-overflow");
        let result = publish_root(dir.path(), &root_max, &k, "overflow-test");
        assert!(result.is_ok());

        let loaded = read_root(dir.path()).expect("read root");
        assert_eq!(loaded.epoch, ControlEpoch(u64::MAX));
        assert_eq!(loaded.marker_stream_head_seq, u64::MAX.saturating_sub(1));
    }

    #[test]
    fn test_bootstrap_zero_width_unicode_in_publisher() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        let mut root = root(102, 1020, "zw-unicode");

        root.publisher_id = "legit\u{200b}\u{feff}\u{200c}publisher".to_string();

        let result = publish_root(dir.path(), &root, &k, "zero-width-test");
        assert!(result.is_ok());

        let cfg = RootAuthConfig::strict(k, ControlEpoch(102));
        let bootstrap_result = bootstrap_root(dir.path(), &cfg);
        assert!(bootstrap_result.is_ok());

        let bootstrapped = bootstrap_result.unwrap();
        assert_eq!(
            bootstrapped.root.publisher_id,
            "legit\u{200b}\u{feff}\u{200c}publisher"
        );
    }

    #[test]
    fn test_publish_malformed_json_resilience() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        let root = root(103, 1030, "json-corruption");

        publish_root(dir.path(), &root, &k, "corruption-test").expect("initial publish");

        let auth_path = root_auth_path(dir.path());
        let corrupt_json =
            r#"{"epoch": 103, "publisher": "unclosed_string, "timestamp": malformed}"#;
        fs::write(&auth_path, corrupt_json).expect("write corrupt auth json");

        let cfg = RootAuthConfig::strict(k, ControlEpoch(103));
        let result = bootstrap_root(dir.path(), &cfg);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), "ROOT_BOOTSTRAP_AUTH_FAILED");
    }

    #[test]
    fn test_concurrent_publish_atomic_guarantees() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();

        use std::sync::{Arc, Barrier};
        use std::thread;

        let dir_path = Arc::new(dir.path().to_path_buf());
        let key_arc = Arc::new(k);
        let barrier = Arc::new(Barrier::new(3));

        let handles: Vec<_> = (0..3)
            .map(|i| {
                let path = Arc::clone(&dir_path);
                let key = Arc::clone(&key_arc);
                let barrier = Arc::clone(&barrier);

                thread::spawn(move || {
                    let root = root(104 + i, 1040 + i * 10, &format!("concurrent-{}", i));
                    barrier.wait();
                    publish_root(&path, &root, &key, &format!("thread-{}", i))
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let successes = results.iter().filter(|r| r.is_ok()).count();

        assert!(successes >= 1);

        let final_root = read_root(dir.path()).expect("read final root");
        assert!(final_root.epoch >= ControlEpoch(104) && final_root.epoch <= ControlEpoch(106));
    }

    #[test]
    fn test_bootstrap_path_traversal_protection() {
        use crate::security::constant_time;
        use std::path::PathBuf;

        // Create temp directory structure
        let base_dir = TempDir::new().expect("tempdir");
        let secure_dir = base_dir.path().join("secure");
        fs::create_dir_all(&secure_dir).expect("create secure dir");

        let k = key();
        let root = root(105, 1050, "path-traversal");

        // Publish in secure directory
        publish_root(&secure_dir, &root, &k, "traversal-test").expect("publish");

        let malicious_path = PathBuf::from("../../../etc/passwd");
        let traversal_dir = base_dir.path().join(&malicious_path);

        let cfg = RootAuthConfig::strict(k, ControlEpoch(105));
        let result = bootstrap_root(&traversal_dir, &cfg);

        assert!(result.is_err());
    }

    #[test]
    fn test_publish_empty_values_edge_cases() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();

        let mut minimal_root = root(0, 0, "");
        minimal_root.marker_stream_head_hash.clear();
        minimal_root.publisher_id.clear();

        let result = publish_root(dir.path(), &minimal_root, &k, "");

        assert!(result.is_ok());

        let loaded = read_root(dir.path()).expect("read root");
        assert_eq!(loaded.epoch, ControlEpoch(0));
        assert_eq!(loaded.publisher_id, "");
        assert_eq!(loaded.marker_stream_head_hash, "");
    }
}
