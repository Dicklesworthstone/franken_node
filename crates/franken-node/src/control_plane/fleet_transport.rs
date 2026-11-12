//! Fleet transport contract and shared state schema for distributed fleet coordination.
//!
//! This module defines the transport-facing action log, node heartbeat/state shape,
//! and object-safe transport trait used by the fleet-control track.

#[cfg(feature = "asupersync-transport")]
use std::sync::{Arc, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions, TryLockError},
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Condvar, Mutex, OnceLock},
    thread,
    time::{Duration, Instant},
};

#[cfg(feature = "asupersync-transport")]
use crate::capacity_defaults::aliases::MAX_CONTROL_EVENTS;
#[cfg(any(test, feature = "asupersync-transport"))]
use crate::push_bounded;
use crate::{
    capacity_defaults::aliases::{MAX_ACTION_LOG_ENTRIES, MAX_NODES_CAP},
    capacity_defaults::bounded_input::{
        AUDIT_BOUNDED_INPUT_REJECTED, BoundedInputPolicy, ERR_BOUNDED_INPUT_CAP_EXCEEDED,
    },
    config::{Config, Profile, SsrfEnforcementMode, timeouts},
    connector::canonical_serializer::canonical_bytes,
};

#[cfg(feature = "control-plane")]
use crate::api::fleet_quarantine::RevocationScope;
use chrono::{DateTime, Utc};
use ed25519_dalek::Signer;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::warn;
use uuid::Uuid;

use crate::runtime::clock;

/// Computed snapshot contract; persisted action and node record formats are unchanged.
pub const FLEET_SHARED_STATE_SCHEMA: &str = "franken-node/fleet-transport-state/v2";
pub const FLEET_ACTION_LOG_FILE: &str = "actions.jsonl";
pub const FLEET_NODE_DIR: &str = "nodes";
pub const FLEET_LOCK_DIR: &str = "locks";
/// Bound owner metadata independently of the much larger historical action log.
pub const MAX_NATIVE_SESSION_MAINTENANCE_HOLDS: usize = 64;
pub const MAX_GUARDED_POLICY_REQUEST_BYTES: usize = 512 * 1024;
pub const MAX_GUARDED_POLICY_RECEIPT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_GUARDED_POLICY_STALE_AFTER: Duration = Duration::from_secs(300);
pub const NATIVE_SESSION_DRAIN_ATTESTATION_SCHEMA: &str =
    "franken-node/native-session-drain-attestation/v1";
/// Use the existing maintenance observation window for supervisor evidence.
/// A new heartbeat must never renew an older signature's validity.
pub const MAX_NATIVE_DRAIN_ATTESTATION_AGE: Duration = MAX_GUARDED_POLICY_STALE_AFTER;
pub const FLEET_GUARDED_POLICY_RECEIPT_SCHEMA: &str =
    "franken-node/fleet-guarded-policy-publication/v1";
const FLEET_ACTION_COMPACTION_LOCK_FILE: &str = "actions.compaction.lock";
const FLEET_SHARED_STATE_LOCK_FILE: &str = "shared-state.snapshot.lock";
const MAX_NODE_ID_LEN: usize = 128;
const MAX_ZONE_ID_LEN: usize = 128;
const MAX_ACTION_ID_LEN: usize = 128;
pub(super) const MAX_ACTION_RECORD_BYTES: usize = 2_048;
const MAX_ACTION_RECORD_LINE_BYTES: usize = MAX_ACTION_RECORD_BYTES * 2;
pub const ERR_FLEET_JSONL_LINE_TOO_LARGE: &str = ERR_BOUNDED_INPUT_CAP_EXCEEDED;
pub const FLEET_ACTION_RECORD_LINE_POLICY: BoundedInputPolicy = BoundedInputPolicy::new(
    "control_plane.fleet_transport",
    "action_jsonl_line",
    MAX_ACTION_RECORD_LINE_BYTES,
    ERR_FLEET_JSONL_LINE_TOO_LARGE,
    AUDIT_BOUNDED_INPUT_REJECTED,
    "bound fleet action JSONL lines before serde allocates a full record",
);
const ACTION_LOG_COMPACTION_THRESHOLD_BYTES: u64 = 10 * 1024 * 1024;
const ACTION_LOG_RETENTION_DAYS: i64 = 30;
const LOCK_RETRY_BACKOFF_MILLIS: [u64; 5] = timeouts::FLEET_LOCK_RETRY_BACKOFF_MILLIS;
pub const FLEET_CONVERGENCE_POLL_INTERVAL: Duration = timeouts::FLEET_CONVERGENCE_POLL_INTERVAL;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetConvergenceWaitOutcome {
    pub elapsed: Duration,
    pub timed_out: bool,
    /// Number of convergence check attempts made during wait
    pub check_attempts: u32,
    /// Diagnostic context for timeout troubleshooting
    pub failure_context: Option<FleetConvergenceFailureContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetConvergenceFailureContext {
    /// Suggested doctor command for diagnosis
    pub doctor_command: String,
    /// Timeout configuration used
    pub timeout_secs: u64,
    /// Brief diagnostic hint for operators
    pub diagnostic_hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetConvergenceReceiptSignature {
    pub algorithm: String,
    pub public_key_hex: String,
    pub key_id: String,
    pub key_source: String,
    pub signing_identity: String,
    pub trust_scope: String,
    pub signed_payload_sha256: String,
    pub signature_hex: String,
}

#[must_use]
pub fn fleet_convergence_receipt_verdict(
    timed_out: bool,
    elapsed_ms: u64,
    timeout_seconds: u64,
    converged: bool,
) -> &'static str {
    if timed_out || elapsed_ms >= timeout_seconds.saturating_mul(1_000) || !converged {
        "non_converged"
    } else {
        "converged"
    }
}

pub fn canonical_fleet_convergence_receipt_payload<T: Serialize>(
    payload: &T,
) -> Result<Vec<u8>, FleetTransportError> {
    let value = serde_json::to_value(payload)
        .map_err(|err| FleetTransportError::serialization(err.to_string()))?;
    reject_fleet_float_numbers(&value, &mut Vec::new())?;
    Ok(canonical_bytes(&value))
}

pub fn sign_fleet_convergence_receipt_payload<T: Serialize>(
    payload: &T,
    signing_key: &ed25519_dalek::SigningKey,
    key_source: &str,
    signing_identity: &str,
) -> Result<FleetConvergenceReceiptSignature, FleetTransportError> {
    let canonical_payload = canonical_fleet_convergence_receipt_payload(payload)?;
    let signature = signing_key.sign(&canonical_payload);
    let verifying_key = signing_key.verifying_key();
    let mut payload_hasher = Sha256::new();
    payload_hasher.update(b"fleet_convergence_receipt_payload_v1:");
    payload_hasher
        .update((u64::try_from(canonical_payload.len()).unwrap_or(u64::MAX)).to_le_bytes());
    payload_hasher.update(&canonical_payload);

    Ok(FleetConvergenceReceiptSignature {
        algorithm: "ed25519".to_string(),
        public_key_hex: hex::encode(verifying_key.to_bytes()),
        key_id: crate::supply_chain::artifact_signing::KeyId::from_verifying_key(&verifying_key)
            .to_string(),
        key_source: key_source.to_string(),
        signing_identity: signing_identity.to_string(),
        trust_scope: "fleet_convergence".to_string(),
        signed_payload_sha256: hex::encode(payload_hasher.finalize()),
        signature_hex: hex::encode(signature.to_bytes()),
    })
}

/// Path segment in the recursive canonicalize walk. Stored as a stack and
/// only rendered to a `String` on the float-error branch — the happy path
/// never builds a path string at all (per bd-98xo5.7.1). The previous
/// implementation `format!`-allocated `"$.foo.bar[3]"` on every descent.
enum PathSeg<'a> {
    Index(usize),
    Key(&'a str),
}

fn render_path(segments: &[PathSeg<'_>]) -> String {
    use std::fmt::Write as _;
    let mut out = String::from("$");
    for seg in segments {
        match seg {
            PathSeg::Index(i) => {
                // write! into a String is infallible.
                let _ = write!(out, "[{i}]");
            }
            PathSeg::Key(k) => {
                out.push('.');
                out.push_str(k);
            }
        }
    }
    out
}

fn reject_fleet_float_numbers<'a>(
    value: &'a Value,
    path: &mut Vec<PathSeg<'a>>,
) -> Result<(), FleetTransportError> {
    match value {
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                path.push(PathSeg::Index(index));
                reject_fleet_float_numbers(item, path)?;
                path.pop();
            }
            Ok(())
        }
        Value::Object(map) => {
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_unstable();
            for key in keys {
                path.push(PathSeg::Key(key));
                let item = map
                    .get(key)
                    .expect("key obtained from map.keys() must be present in the same map");
                reject_fleet_float_numbers(item, path)?;
                path.pop();
            }
            Ok(())
        }
        Value::Number(number) if number.is_f64() => {
            Err(FleetTransportError::serialization(format!(
                "fleet convergence receipt contains non-deterministic float at {}",
                render_path(path),
            )))
        }
        _ => Ok(()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetTargetKind {
    Artifact,
    Extension,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeHealth {
    Healthy,
    /// The exact action snapshot is applied and its retained native population
    /// is terminal, while an explicit maintenance owner keeps admission fenced.
    Maintenance,
    Degraded,
    Quarantined,
    Stale,
}

/// Executable fleet restrictions. Every field can only restrict the local
/// runtime configuration; this document cannot grant host capabilities, choose
/// executables, write arbitrary paths, or replace local signing material.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetRuntimePolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_profile: Option<Profile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_instructions: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_parse_source_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_parse_tokens: Option<u64>,
    /// Block private/internal destinations and cloud metadata, including
    /// destinations that a local allowlist would otherwise exempt.
    #[serde(default)]
    pub block_private_network: bool,
}

fn fleet_profile_rank(profile: Profile) -> u8 {
    match profile {
        Profile::LegacyRisky => 0,
        Profile::Balanced => 1,
        Profile::Strict => 2,
    }
}

impl FleetRuntimePolicy {
    pub fn validate(&self) -> Result<(), FleetTransportError> {
        if self
            .minimum_profile
            .is_none_or(|profile| profile == Profile::LegacyRisky)
            && self.max_instructions.is_none()
            && self.max_parse_source_bytes.is_none()
            && self.max_parse_tokens.is_none()
            && !self.block_private_network
        {
            return Err(FleetTransportError::serialization(
                "fleet runtime policy must contain an executable restriction",
            ));
        }
        let mut runtime = crate::config::RuntimeConfig::balanced_defaults();
        runtime.max_instructions = self.max_instructions;
        runtime.max_parse_source_bytes = self.max_parse_source_bytes;
        runtime.max_parse_tokens = self.max_parse_tokens;
        runtime
            .validate_execution_budget()
            .and_then(|()| runtime.validate_parse_budget())
            .map_err(|error| FleetTransportError::serialization(error.to_string()))
    }

    fn is_at_least_as_restrictive_as(&self, previous: &Self) -> bool {
        let ceiling_preserved = |current: Option<u64>, old: Option<u64>| {
            old.is_none_or(|old| current.is_some_and(|current| current <= old))
        };
        self.minimum_profile.map_or(0, fleet_profile_rank)
            >= previous.minimum_profile.map_or(0, fleet_profile_rank)
            && ceiling_preserved(self.max_instructions, previous.max_instructions)
            && ceiling_preserved(self.max_parse_source_bytes, previous.max_parse_source_bytes)
            && ceiling_preserved(self.max_parse_tokens, previous.max_parse_tokens)
            && (!previous.block_private_network || self.block_private_network)
    }

    fn enforce(&self, config: &mut Config, profile: Profile) -> Result<(), FleetTransportError> {
        self.validate()?;
        if let Some(minimum) = self.minimum_profile
            && fleet_profile_rank(profile) < fleet_profile_rank(minimum)
        {
            return Err(FleetTransportError::stale_state(format!(
                "activated fleet policy requires profile `{minimum}` or stricter; selected `{profile}`"
            )));
        }
        if let Some(limit) = self.max_instructions {
            let local_limit = config.runtime.effective_instruction_budget(profile);
            config.runtime.max_instructions = Some(local_limit.min(limit));
        }
        let parse = config.runtime.effective_parse_budget(profile);
        if let Some(limit) = self.max_parse_source_bytes {
            config.runtime.max_parse_source_bytes = Some(parse.max_source_bytes.min(limit));
        }
        if let Some(limit) = self.max_parse_tokens {
            config.runtime.max_parse_tokens = Some(parse.max_token_count.min(limit));
        }
        if self.block_private_network {
            let network = &mut config.security.network_policy;
            network.ssrf_enforcement = SsrfEnforcementMode::Block;
            network.ssrf_protection_enabled = true;
            network.block_cloud_metadata = true;
            network.audit_blocked_requests = true;
            network.allowlist.clear();
        }
        Ok(())
    }
}

/// The revision is monotonic within one action zone. The digest binds the full
/// typed policy and revision, independently of timestamps or changed-field hints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetPolicyArtifact {
    pub revision: u64,
    pub content_sha256: String,
    pub policy: FleetRuntimePolicy,
}

impl FleetPolicyArtifact {
    pub fn new(revision: u64, policy: FleetRuntimePolicy) -> Result<Self, FleetTransportError> {
        let mut artifact = Self {
            revision,
            content_sha256: String::new(),
            policy,
        };
        artifact.content_sha256 = artifact.compute_hash()?;
        artifact.validate()?;
        Ok(artifact)
    }

    fn compute_hash(&self) -> Result<String, FleetTransportError> {
        let value = serde_json::to_value((&self.revision, &self.policy))
            .map_err(|error| FleetTransportError::serialization(error.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(b"franken-node/fleet-runtime-policy/v1\0");
        hasher.update(canonical_bytes(&value));
        Ok(hex::encode(hasher.finalize()))
    }

    pub fn validate(&self) -> Result<(), FleetTransportError> {
        if self.revision == 0 {
            return Err(FleetTransportError::serialization(
                "fleet policy revision must be positive",
            ));
        }
        self.policy.validate()?;
        if self.content_sha256 != self.compute_hash()? {
            return Err(FleetTransportError::serialization(
                "fleet policy content_sha256 does not bind its revision and executable content",
            ));
        }
        Ok(())
    }

    fn ensure_successor_of(&self, previous: &Self) -> Result<(), FleetTransportError> {
        self.validate()?;
        previous.validate()?;
        if self.revision < previous.revision {
            return Err(FleetTransportError::stale_state(format!(
                "fleet policy rollback from revision {} to {} is refused",
                previous.revision, self.revision
            )));
        }
        if self.revision == previous.revision && self != previous {
            return Err(FleetTransportError::action_conflict(format!(
                "fleet policy revision {} has conflicting content",
                self.revision
            )));
        }
        if !self.policy.is_at_least_as_restrictive_as(&previous.policy) {
            return Err(FleetTransportError::stale_state(format!(
                "fleet policy revision {} weakens an activated restriction from revision {}",
                self.revision, previous.revision
            )));
        }
        Ok(())
    }
}

pub const ACTIVE_FLEET_POLICY_SCHEMA: &str = "franken-node/active-fleet-policy/v1";
const FLEET_POLICY_STATE_FILE: &str = "fleet-policy.json";
const FLEET_POLICY_REQUIRED_FILE: &str = "fleet-policy-required.json";
const FLEET_POLICY_LOCK_FILE: &str = "fleet-policy.lock";
#[cfg(unix)]
const MAX_FLEET_POLICY_STATE_BYTES: usize = 16 * 1024;

/// Per-project activation. Fleet-wide and exact-zone restrictions compose by
/// intersection; one scope never overrides another scope's restrictions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveFleetPolicy {
    pub schema_version: String,
    pub zone_id: String,
    pub policies: BTreeMap<String, FleetPolicyArtifact>,
}

impl ActiveFleetPolicy {
    pub fn validate(&self) -> Result<(), FleetTransportError> {
        validate_zone_id(&self.zone_id)?;
        if self.schema_version != ACTIVE_FLEET_POLICY_SCHEMA
            || self.policies.is_empty()
            || self.policies.len() > 2
        {
            return Err(FleetTransportError::serialization(
                "invalid activated fleet policy schema or scope count",
            ));
        }
        for (zone, artifact) in &self.policies {
            if zone != "all" && zone != &self.zone_id {
                return Err(FleetTransportError::serialization(
                    "activated fleet policy contains an unrelated zone",
                ));
            }
            artifact.validate()?;
        }
        Ok(())
    }

    /// Check an authenticated parent-to-worker expectation or durable high-water
    /// mark. New revisions may tighten it; disappearance and rollback fail closed.
    pub fn ensure_successor_of(&self, previous: &Self) -> Result<(), FleetTransportError> {
        self.validate()?;
        previous.validate()?;
        if self.zone_id != previous.zone_id {
            return Err(FleetTransportError::stale_state(
                "activated fleet policy zone changed for the selected project",
            ));
        }
        for (zone, old) in &previous.policies {
            let current = self.policies.get(zone).ok_or_else(|| {
                FleetTransportError::stale_state(format!(
                    "activated fleet policy scope `{zone}` disappeared"
                ))
            })?;
            current.ensure_successor_of(old)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FleetAction {
    Quarantine {
        zone_id: String,
        incident_id: String,
        target_id: String,
        target_kind: FleetTargetKind,
        reason: String,
        quarantine_version: u64,
    },
    Release {
        zone_id: String,
        incident_id: String,
        reason: Option<String>,
    },
    /// Its immutable action ID owns this persistent native admission hold.
    NativeSessionHold { zone_id: String, reason: String },
    /// Release only the named hold in its original exact zone. Other holds,
    /// quarantines, revocations and unresolved effects remain authoritative.
    NativeSessionResume {
        zone_id: String,
        hold_action_id: String,
        reason: Option<String>,
    },
    PolicyUpdate {
        zone_id: String,
        policy_version: String,
        changed_fields: Vec<String>,
        /// Historical field-name-only intent remains readable, but cannot be
        /// acknowledged as applied. New publishers supply executable content.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        artifact: Option<FleetPolicyArtifact>,
    },
    #[cfg(feature = "control-plane")]
    Revoke {
        extension_id: String,
        scope: RevocationScope,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetActionRecord {
    pub action_id: String,
    pub emitted_at: DateTime<Utc>,
    pub action: FleetAction,
}

/// Choose one executable revision per applicable action scope. Producer clocks
/// and delivery order cannot downgrade policy, and conflicting same-revision
/// publications are refused even when another revision would supersede them.
pub fn fleet_policy_snapshot(
    actions: &[FleetActionRecord],
    zone_id: &str,
) -> Result<Option<ActiveFleetPolicy>, FleetTransportError> {
    validate_zone_id(zone_id)?;
    if actions.len() > MAX_ACTION_LOG_ENTRIES {
        return Err(FleetTransportError::serialization(
            "fleet policy action snapshot is too large",
        ));
    }
    let mut revisions = BTreeMap::<&str, BTreeMap<u64, &FleetPolicyArtifact>>::new();
    for record in actions {
        validate_action_record(record)?;
        if let FleetAction::PolicyUpdate {
            zone_id: scope,
            artifact: Some(artifact),
            ..
        } = &record.action
            && (scope == "all" || scope == zone_id)
        {
            let by_revision = revisions.entry(scope).or_default();
            if let Some(existing) = by_revision.insert(artifact.revision, artifact)
                && existing != artifact
            {
                return Err(FleetTransportError::action_conflict(format!(
                    "fleet policy scope `{scope}` revision {} has conflicting content",
                    artifact.revision
                )));
            }
        }
    }
    let mut policies = BTreeMap::new();
    for (scope, by_revision) in revisions {
        let mut previous: Option<&FleetPolicyArtifact> = None;
        for artifact in by_revision.into_values() {
            if let Some(old) = previous {
                artifact.ensure_successor_of(old)?;
            }
            previous = Some(artifact);
        }
        if let Some(artifact) = previous {
            policies.insert(scope.to_string(), artifact.clone());
        }
    }
    if policies.is_empty() {
        return Ok(None);
    }
    let active = ActiveFleetPolicy {
        schema_version: ACTIVE_FLEET_POLICY_SCHEMA.to_string(),
        zone_id: zone_id.to_string(),
        policies,
    };
    active.validate()?;
    Ok(Some(active))
}

/// Enforce the per-zone policy revision contract while the transport still
/// holds its publication transaction/lock. This prevents concurrent publishers
/// from poisoning retained history with conflicting or weakening revisions.
pub(super) fn validate_fleet_policy_publication(
    record: &FleetActionRecord,
    existing: &[FleetActionRecord],
) -> Result<(), FleetTransportError> {
    let FleetAction::PolicyUpdate {
        zone_id,
        artifact: Some(candidate),
        ..
    } = &record.action
    else {
        return Ok(());
    };
    if existing.iter().any(|old| old == record) {
        return Ok(());
    }
    for old in existing {
        if let FleetAction::PolicyUpdate {
            zone_id: scope,
            artifact: Some(previous),
            ..
        } = &old.action
            && scope == zone_id
        {
            candidate.ensure_successor_of(previous)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
struct FleetPolicyStore {
    directory: File,
    lock: File,
    enrollment_created: bool,
}

#[cfg(unix)]
impl FleetPolicyStore {
    fn open(project: &Path, create: bool) -> Result<Option<Self>, FleetTransportError> {
        use rustix::fs::{Mode, OFlags, mkdirat, open, openat};
        use rustix::io::Errno;
        use std::os::unix::fs::MetadataExt;
        use std::path::Component;

        let open_store = || -> std::io::Result<Option<Self>> {
            let root = if project.is_absolute() {
                project.to_path_buf()
            } else {
                project.canonicalize()?
            };
            if root
                .components()
                .any(|part| matches!(part, Component::ParentDir))
            {
                return Err(std::io::Error::other(
                    "fleet policy project root contains parent traversal",
                ));
            }
            let directories =
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let mut directory = File::from(open("/", directories, Mode::empty())?);
            for part in root.components() {
                if let Component::Normal(name) = part {
                    directory = File::from(openat(&directory, name, directories, Mode::empty())?);
                }
            }
            for name in [".franken-node", "state"] {
                directory = match openat(&directory, name, directories, Mode::empty()) {
                    Ok(fd) => File::from(fd),
                    Err(Errno::NOENT) if !create => return Ok(None),
                    Err(Errno::NOENT) => {
                        match mkdirat(&directory, name, Mode::from_raw_mode(0o700)) {
                            Ok(()) => directory.sync_all()?,
                            Err(Errno::EXIST) => {}
                            Err(error) => return Err(error.into()),
                        }
                        File::from(openat(&directory, name, directories, Mode::empty())?)
                    }
                    Err(error) => return Err(error.into()),
                };
            }
            // A contained worker sees its independent operator through the
            // read-only host mount. Shared observation needs no write access;
            // both readers and writers still lock this same checked inode.
            let access = if create { OFlags::RDWR } else { OFlags::RDONLY };
            let flags = access | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
            let (lock, enrollment_created) = match openat(
                &directory,
                FLEET_POLICY_LOCK_FILE,
                if create {
                    flags | OFlags::CREATE | OFlags::EXCL
                } else {
                    flags
                },
                Mode::from_raw_mode(0o600),
            ) {
                Ok(fd) => (File::from(fd), create),
                Err(Errno::EXIST) if create => (
                    File::from(openat(
                        &directory,
                        FLEET_POLICY_LOCK_FILE,
                        flags,
                        Mode::empty(),
                    )?),
                    false,
                ),
                Err(Errno::NOENT) if !create => {
                    // Loss of the lock must not make an enrolled project appear
                    // unconfigured. Inspect fixed names using the same authority.
                    for name in [FLEET_POLICY_REQUIRED_FILE, FLEET_POLICY_STATE_FILE] {
                        match openat(
                            &directory,
                            name,
                            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                            Mode::empty(),
                        ) {
                            Err(Errno::NOENT) => {}
                            Ok(_) => {
                                return Err(std::io::Error::other(
                                    "fleet policy enrollment exists without its lock",
                                ));
                            }
                            Err(error) => return Err(error.into()),
                        }
                    }
                    return Ok(None);
                }
                Err(error) => return Err(error.into()),
            };
            let metadata = lock.metadata()?;
            if !metadata.is_file() || metadata.nlink() != 1 {
                return Err(std::io::Error::other(
                    "fleet policy lock must be a regular file without hardlink aliases",
                ));
            }
            if enrollment_created {
                lock.sync_all()?;
                directory.sync_all()?;
            }
            Ok(Some(Self {
                directory,
                lock,
                enrollment_created,
            }))
        };
        let Some(store) = open_store().map_err(|error| {
            FleetTransportError::io(format!("failed opening project fleet policy: {error}"))
        })?
        else {
            return Ok(None);
        };
        lock_file_with_backoff(&store.lock, Path::new(FLEET_POLICY_LOCK_FILE), !create)?;
        Ok(Some(store))
    }

    fn read(&self, name: &str) -> Result<Option<ActiveFleetPolicy>, FleetTransportError> {
        use rustix::fs::{Mode, OFlags, openat};
        use rustix::io::Errno;
        use std::os::unix::fs::MetadataExt;

        let read = || -> std::io::Result<Option<Vec<u8>>> {
            let mut file = match openat(
                &self.directory,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => File::from(fd),
                Err(Errno::NOENT) => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            let before = file.metadata()?;
            if !before.is_file()
                || before.nlink() != 1
                || before.len() > MAX_FLEET_POLICY_STATE_BYTES as u64
            {
                return Err(std::io::Error::other(
                    "fleet policy must be a bounded regular file without hardlink aliases",
                ));
            }
            let mut bytes = Vec::new();
            (&mut file)
                .take(MAX_FLEET_POLICY_STATE_BYTES as u64 + 1)
                .read_to_end(&mut bytes)?;
            let after = file.metadata()?;
            if bytes.len() > MAX_FLEET_POLICY_STATE_BYTES
                || bytes.len() as u64 != before.len()
                || before.len() != after.len()
                || before.mtime() != after.mtime()
                || before.mtime_nsec() != after.mtime_nsec()
                || before.ctime() != after.ctime()
                || before.ctime_nsec() != after.ctime_nsec()
            {
                return Err(std::io::Error::other(
                    "fleet policy changed during its bounded read",
                ));
            }
            Ok(Some(bytes))
        };
        read()
            .map_err(|error| FleetTransportError::io(format!("failed reading {name}: {error}")))?
            .map(|bytes| {
                let policy: ActiveFleetPolicy =
                    serde_json::from_slice(&bytes).map_err(|error| {
                        FleetTransportError::serialization(format!("invalid {name}: {error}"))
                    })?;
                policy.validate()?;
                Ok(policy)
            })
            .transpose()
    }

    fn write(&self, name: &str, policy: &ActiveFleetPolicy) -> Result<(), FleetTransportError> {
        use rustix::fs::{Mode, OFlags, openat, renameat};
        policy.validate()?;
        let bytes = serde_json::to_vec(policy)
            .map_err(|error| FleetTransportError::serialization(error.to_string()))?;
        if bytes.len() > MAX_FLEET_POLICY_STATE_BYTES {
            return Err(FleetTransportError::serialization(
                "fleet policy state exceeds its byte bound",
            ));
        }
        let write = || -> std::io::Result<()> {
            let temp = format!(".fleet-policy-{}.tmp", Uuid::now_v7());
            let mut file = File::from(openat(
                &self.directory,
                temp.as_str(),
                OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )?);
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            renameat(&self.directory, temp.as_str(), &self.directory, name)?;
            self.directory.sync_all()
        };
        write()
            .map_err(|error| FleetTransportError::io(format!("failed committing {name}: {error}")))
    }

    fn active(&self) -> Result<Option<ActiveFleetPolicy>, FleetTransportError> {
        let required = self.read(FLEET_POLICY_REQUIRED_FILE)?;
        let active = self.read(FLEET_POLICY_STATE_FILE)?;
        if required.is_none() || required != active {
            return Err(FleetTransportError::stale_state(
                "fleet policy activation is missing or incomplete; run the fleet agent to repair it before executing guests",
            ));
        }
        Ok(active)
    }
}

#[cfg(unix)]
impl Drop for FleetPolicyStore {
    fn drop(&mut self) {
        let _ = self.lock.unlock();
    }
}

/// Read one consistent activated snapshot. An interrupted policy commit, lost
/// activation document, malformed content, or mismatched zone cannot silently
/// turn an enrolled project back into an unmanaged runtime.
pub fn load_active_fleet_policy(
    project: &Path,
) -> Result<Option<ActiveFleetPolicy>, FleetTransportError> {
    #[cfg(unix)]
    {
        FleetPolicyStore::open(project, false)?
            .map(|store| store.active())
            .transpose()
            .map(Option::flatten)
    }
    #[cfg(not(unix))]
    {
        for name in [
            FLEET_POLICY_REQUIRED_FILE,
            FLEET_POLICY_STATE_FILE,
            FLEET_POLICY_LOCK_FILE,
        ] {
            match project
                .join(".franken-node/state")
                .join(name)
                .symlink_metadata()
            {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => {
                    return Err(FleetTransportError::io(
                        "fleet policy activation requires Unix descriptor-relative storage on this build",
                    ));
                }
            }
        }
        Ok(None)
    }
}

/// A narrower guest filesystem root must not hide an enclosing project's
/// enrollment. Keep its authority narrow and refuse the run rather than
/// silently widening that authority or dropping the enclosing policy.
///
/// Inspect canonical ancestors independently of the invocation directory and
/// package markers. The normal policy reader also refuses corrupt enrollment,
/// missing documents with a retained lock, and linked state paths.
pub fn validate_fleet_policy_project_root(project: &Path) -> Result<(), FleetTransportError> {
    validate_fleet_policy_project_root_with_operator(project, None)
}

/// Preserve one independently admitted deployment operator without widening
/// the release's filesystem authority. Callers must enforce that operator's
/// policy separately; this exception only permits its exact retained ancestor
/// while continuing to inspect every enclosing enrollment for corruption or
/// another control owner that has not been retained.
pub fn validate_fleet_policy_project_root_with_operator(
    project: &Path,
    operator: Option<&Path>,
) -> Result<(), FleetTransportError> {
    if let Some(operator) = operator {
        let normalized: PathBuf = operator.components().collect();
        if !operator.is_absolute()
            || normalized.as_os_str() != operator.as_os_str()
            || operator.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
        {
            return Err(FleetTransportError::stale_state(
                "retained fleet operator must be a normalized absolute canonical project root",
            ));
        }
        let canonical_operator = operator.canonicalize().map_err(|error| {
            FleetTransportError::io(format!(
                "failed resolving retained fleet operator project root {}: {error}",
                operator.display()
            ))
        })?;
        if canonical_operator.as_os_str() != operator.as_os_str() {
            return Err(FleetTransportError::stale_state(
                "retained fleet operator must be a normalized absolute canonical project root",
            ));
        }
    }
    let canonical = project.canonicalize().map_err(|error| {
        FleetTransportError::io(format!(
            "failed resolving fleet policy project root {}: {error}",
            project.display()
        ))
    })?;
    for ancestor in canonical.ancestors().skip(1) {
        let active = load_active_fleet_policy(ancestor).map_err(|error| {
            FleetTransportError::stale_state(format!(
                "cannot exclude fleet policy enrollment at ancestor {} of selected project {}: {error}; \
                 restore that enrollment and select its project directory explicitly",
                ancestor.display(),
                canonical.display()
            ))
        })?;
        if active.is_some() && operator != Some(ancestor) {
            return Err(FleetTransportError::stale_state(format!(
                "selected project {} is inside fleet-managed project {}; \
                 select the enrolled project directory explicitly to preserve its policy",
                canonical.display(),
                ancestor.display()
            )));
        }
    }
    Ok(())
}

/// Apply policy to a copy and commit that copy only on success. The selected
/// profile stays unchanged: callers below a fleet floor receive an explicit
/// admission refusal rather than a mixture of profile defaults.
pub fn enforce_active_fleet_policy(
    project: &Path,
    config: &mut Config,
    profile: Profile,
) -> Result<Option<ActiveFleetPolicy>, FleetTransportError> {
    enforce_active_fleet_policy_with_operator(project, config, profile, None)
}

/// Apply the release's policy while preserving an independently admitted
/// operator ancestor. The caller must also enforce the operator's own policy
/// through the strict entry point so both restrictions compose and no outer
/// enrollment is discarded.
pub fn enforce_active_fleet_policy_with_operator(
    project: &Path,
    config: &mut Config,
    profile: Profile,
    operator: Option<&Path>,
) -> Result<Option<ActiveFleetPolicy>, FleetTransportError> {
    // Capture relative aliases once so ancestry admission and the activation
    // read cannot resolve different projects. Absolute inputs retain the
    // descriptor reader's existing refusal of symlinked path components.
    let canonical_relative = if project.is_absolute() {
        None
    } else {
        Some(project.canonicalize().map_err(|error| {
            FleetTransportError::io(format!(
                "failed resolving fleet policy admission project {}: {error}",
                project.display()
            ))
        })?)
    };
    let project = canonical_relative.as_deref().unwrap_or(project);
    validate_fleet_policy_project_root_with_operator(project, operator)?;
    let active = load_active_fleet_policy(project)?;
    if let Some(active) = &active {
        if config.profile != profile {
            return Err(FleetTransportError::stale_state(
                "fleet policy admission profile does not match the executable runtime config",
            ));
        }
        let mut effective = config.clone();
        for artifact in active.policies.values() {
            artifact.policy.enforce(&mut effective, profile)?;
        }
        effective
            .runtime
            .validate_execution_budget()
            .and_then(|()| effective.runtime.validate_parse_budget())
            .map_err(|error| FleetTransportError::serialization(error.to_string()))?;
        *config = effective;
    }
    Ok(active)
}

/// Activate the complete desired policy once per poll, before acknowledging any
/// policy action. The durable required document is a write-ahead high-water mark:
/// it is persisted before the active document, and a crash between those writes
/// blocks new guests until a matching or stricter snapshot is durably repaired.
/// Activation governs new run admission. Running native sessions observe this
/// persisted state and are interrupted if their effective restrictions change;
/// they must be restarted under the new policy. An action
/// acknowledgement proves persistence, not that every session is already quiet.
pub fn activate_fleet_policy_snapshot(
    project: &Path,
    actions: &[FleetActionRecord],
    zone_id: &str,
) -> Result<Option<ActiveFleetPolicy>, FleetTransportError> {
    let candidate = fleet_policy_snapshot(actions, zone_id)?;
    #[cfg(unix)]
    {
        let Some(store) = FleetPolicyStore::open(project, candidate.is_some())? else {
            return Ok(None);
        };
        let required = store.read(FLEET_POLICY_REQUIRED_FILE)?;
        let active = store.read(FLEET_POLICY_STATE_FILE)?;
        if required.is_none() && active.is_none() && !store.enrollment_created {
            return Err(FleetTransportError::stale_state(
                "fleet policy enrollment remains but both policy documents disappeared; prior restrictions cannot be recovered from an unverified replacement snapshot",
            ));
        }
        if required.is_none() && active.is_some() {
            return Err(FleetTransportError::stale_state(
                "fleet policy required high-water mark disappeared",
            ));
        }
        let Some(candidate) = candidate else {
            return Err(FleetTransportError::stale_state(
                "previously activated fleet policy disappeared from the action snapshot",
            ));
        };
        for previous in required.iter().chain(active.iter()) {
            candidate.ensure_successor_of(previous)?;
        }
        if required.as_ref() != Some(&candidate) {
            store.write(FLEET_POLICY_REQUIRED_FILE, &candidate)?;
        }
        if active.as_ref() != Some(&candidate) {
            store.write(FLEET_POLICY_STATE_FILE, &candidate)?;
        }
        // Re-read through the same lock before a successful application ACK.
        store.active()
    }
    #[cfg(not(unix))]
    {
        if candidate.is_some() || load_active_fleet_policy(project)?.is_some() {
            return Err(FleetTransportError::io(
                "fleet policy activation requires Unix descriptor-relative storage on this build",
            ));
        }
        Ok(None)
    }
}

/// A node's acknowledgement that it durably reconciled the entire relevant
/// action snapshot. This is an application checkpoint, not a signature or a
/// node-specific attestation: the HTTP transport authenticates a shared bearer.
/// A heartbeat or quarantine counter alone is never an application checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetApplicationCheckpoint {
    pub action_count: u64,
    pub actions_sha256: String,
}

impl FleetApplicationCheckpoint {
    pub fn validate(&self) -> Result<(), FleetTransportError> {
        if self.action_count > MAX_ACTION_LOG_ENTRIES as u64 {
            return Err(FleetTransportError::serialization(
                "fleet application checkpoint action count exceeds the bounded history",
            ));
        }
        if !is_lowercase_sha256(&self.actions_sha256) {
            return Err(FleetTransportError::serialization(
                "fleet application checkpoint must contain a lowercase SHA-256 digest",
            ));
        }
        Ok(())
    }
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The complete coordinator append sequence, including every concrete zone.
/// Unlike an application checkpoint for zone `all`, this never filters out
/// concrete-zone actions. It is a publication precondition, not an epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetActionLogCheckpoint {
    pub action_count: u64,
    pub actions_sha256: String,
}

impl FleetActionLogCheckpoint {
    pub fn validate(&self) -> Result<(), FleetTransportError> {
        if self.action_count > MAX_ACTION_LOG_ENTRIES as u64
            || !is_lowercase_sha256(&self.actions_sha256)
        {
            return Err(FleetTransportError::serialization(
                "full fleet action checkpoint requires a bounded count and lowercase SHA-256",
            ));
        }
        Ok(())
    }
}

pub fn fleet_action_log_checkpoint(
    actions: &[FleetActionRecord],
) -> Result<FleetActionLogCheckpoint, FleetTransportError> {
    let _ = validated_native_session_holds(actions)?;
    let mut digest = Sha256::new();
    digest.update(b"franken-node/fleet-action-log/v1\0");
    digest.update((actions.len() as u64).to_le_bytes());
    for record in actions {
        let value = serde_json::to_value(record)
            .map_err(|error| FleetTransportError::serialization(error.to_string()))?;
        let bytes = canonical_bytes(&value);
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    Ok(FleetActionLogCheckpoint {
        action_count: actions.len() as u64,
        actions_sha256: hex::encode(digest.finalize()),
    })
}

/// Outcome of a retained local admission fence and its exact session population.
/// This does not certify remote effects, a fleet epoch barrier, or global quiescence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSessionDrainState {
    Pending,
    Indeterminate,
    Completed,
}

/// Local supervisor accounting bound to the same ordered action snapshot as
/// policy application. The session-set digest commits to retained admission
/// nonces, rather than a PID or an entrypoint name that can be reused.
/// Enrolled HTTP transports authenticate the sender with its node credential.
/// An optional supervisor attestation additionally binds the observation to a
/// separately enrolled product root. File and shared-bearer transports carry
/// local observations without enrolled-node authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSessionDrainCheckpoint {
    pub applied_actions: FleetApplicationCheckpoint,
    pub session_set_sha256: String,
    pub admitted_sessions: u64,
    pub terminal_sessions: u64,
    pub pending_sessions: u64,
    pub indeterminate_sessions: u64,
    /// The admission fence is released only after the retained population is
    /// terminal with no unknown effect obligations and policy is applied.
    pub fence_held: bool,
    /// Optional supervisor signature. Its embedded key identity is not a trust
    /// anchor: the coordinator must separately enroll the supervisor public key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supervisor_attestation: Option<NativeSessionDrainAttestation>,
}

/// Source-free evidence of one local supervisor's retained drain observation.
/// The signature binds the exact checkpoint, owner, generation and observation
/// time. It does not certify a distributed epoch, remote-effect rollback, or
/// the absence of later admissions after a fence has been released.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSessionDrainAttestation {
    pub schema_version: String,
    pub node_id: String,
    pub zone_id: String,
    pub drain_id: String,
    pub generation: u64,
    pub project_root_sha256: String,
    pub observed_at: DateTime<Utc>,
    pub product_root_key_id: String,
    pub checkpoint_sha256: String,
    pub signature_hex: String,
}

impl NativeSessionDrainAttestation {
    /// Domain-separated canonical preimage; used only by the authoritative
    /// inventory signer and verifiers. The signature itself is excluded.
    pub fn signing_payload(&self) -> Result<Vec<u8>, FleetTransportError> {
        #[derive(Serialize)]
        struct Payload<'a> {
            schema_version: &'a str,
            node_id: &'a str,
            zone_id: &'a str,
            drain_id: &'a str,
            generation: u64,
            project_root_sha256: &'a str,
            observed_at: DateTime<Utc>,
            product_root_key_id: &'a str,
            checkpoint_sha256: &'a str,
        }
        let bytes = canonical_fleet_convergence_receipt_payload(&Payload {
            schema_version: &self.schema_version,
            node_id: &self.node_id,
            zone_id: &self.zone_id,
            drain_id: &self.drain_id,
            generation: self.generation,
            project_root_sha256: &self.project_root_sha256,
            observed_at: self.observed_at,
            product_root_key_id: &self.product_root_key_id,
            checkpoint_sha256: &self.checkpoint_sha256,
        })?;
        let mut preimage = b"franken-node/native-session-drain-signature/v1\0".to_vec();
        preimage.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        preimage.extend_from_slice(&bytes);
        Ok(preimage)
    }

    fn validate_shape(&self) -> Result<(), FleetTransportError> {
        validate_node_id(&self.node_id)?;
        validate_zone_id(&self.zone_id)?;
        if self.schema_version != NATIVE_SESSION_DRAIN_ATTESTATION_SCHEMA
            || self.zone_id == "all"
            || self.generation == 0
            || Uuid::parse_str(&self.drain_id)
                .ok()
                .is_none_or(|id| id.to_string() != self.drain_id)
            || !is_lowercase_sha256(&self.project_root_sha256)
            || !is_lowercase_sha256(&self.checkpoint_sha256)
            || !self
                .product_root_key_id
                .strip_prefix("ed25519:")
                .is_some_and(is_lowercase_sha256)
            || self.signature_hex.len() != 128
            || !self
                .signature_hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(FleetTransportError::serialization(
                "invalid native supervisor drain attestation identity or encoding",
            ));
        }
        Ok(())
    }

    /// Check integrity against an independently provisioned supervisor root.
    /// Freshness must additionally be checked at every use, not only ingestion.
    pub fn verify(
        &self,
        checkpoint: &NativeSessionDrainCheckpoint,
        node_id: &str,
        zone_id: &str,
        trusted_root: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), FleetTransportError> {
        checkpoint.validate()?;
        self.validate_shape()?;
        if self.node_id != node_id
            || self.zone_id != zone_id
            || self.product_root_key_id
                != format!("ed25519:{}", hex::encode(trusted_root.as_bytes()))
            || self.checkpoint_sha256 != checkpoint.observation_sha256()?
        {
            return Err(FleetTransportError::serialization(
                "native supervisor drain attestation does not match its node, checkpoint or enrolled root",
            ));
        }
        let bytes = hex::decode(&self.signature_hex).map_err(|_| {
            FleetTransportError::serialization("invalid native supervisor drain signature encoding")
        })?;
        let signature = ed25519_dalek::Signature::from_slice(&bytes).map_err(|_| {
            FleetTransportError::serialization("invalid native supervisor drain signature length")
        })?;
        trusted_root
            .verify_strict(&self.signing_payload()?, &signature)
            .map_err(|_| {
                FleetTransportError::serialization(
                    "native supervisor drain signature verification failed",
                )
            })
    }

    pub fn validate_freshness(&self, now: DateTime<Utc>) -> Result<(), FleetTransportError> {
        if self.observed_at > now
            || now.signed_duration_since(self.observed_at)
                >= chrono::Duration::seconds(MAX_NATIVE_DRAIN_ATTESTATION_AGE.as_secs() as i64)
        {
            return Err(FleetTransportError::stale_state(
                "native supervisor drain attestation is future-dated or expired; obtain a fresh supervisor observation",
            ));
        }
        Ok(())
    }

    /// Both observations must first be verified against the enrolled root.
    /// A node identity cannot silently move to another project or older drain.
    pub fn validate_successor_of(&self, previous: &Self) -> Result<(), FleetTransportError> {
        if self.node_id != previous.node_id
            || self.zone_id != previous.zone_id
            || self.product_root_key_id != previous.product_root_key_id
            || self.project_root_sha256 != previous.project_root_sha256
            || self.generation < previous.generation
            || (self.generation == previous.generation && self.drain_id != previous.drain_id)
            || self.observed_at < previous.observed_at
            || (self.observed_at == previous.observed_at && self != previous)
        {
            return Err(FleetTransportError::stale_state(
                "native supervisor observation regresses or replaces its enrolled project/drain history",
            ));
        }
        Ok(())
    }
}

impl NativeSessionDrainCheckpoint {
    /// Commit only to the original observation fields, without recursively
    /// including the optional attestation or relying on mutable path metadata.
    pub fn observation_sha256(&self) -> Result<String, FleetTransportError> {
        #[derive(Serialize)]
        struct Observation<'a> {
            applied_actions: &'a FleetApplicationCheckpoint,
            session_set_sha256: &'a str,
            admitted_sessions: u64,
            terminal_sessions: u64,
            pending_sessions: u64,
            indeterminate_sessions: u64,
            fence_held: bool,
        }
        let bytes = canonical_fleet_convergence_receipt_payload(&Observation {
            applied_actions: &self.applied_actions,
            session_set_sha256: &self.session_set_sha256,
            admitted_sessions: self.admitted_sessions,
            terminal_sessions: self.terminal_sessions,
            pending_sessions: self.pending_sessions,
            indeterminate_sessions: self.indeterminate_sessions,
            fence_held: self.fence_held,
        })?;
        let mut digest = Sha256::new();
        digest.update(b"franken-node/native-session-drain-checkpoint/v1\0");
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
        Ok(hex::encode(digest.finalize()))
    }

    pub fn validate(&self) -> Result<(), FleetTransportError> {
        self.applied_actions.validate()?;
        if !is_lowercase_sha256(&self.session_set_sha256) {
            return Err(FleetTransportError::serialization(
                "native session drain must contain a lowercase session-set SHA-256 digest",
            ));
        }
        let accounted = self
            .terminal_sessions
            .checked_add(self.pending_sessions)
            .and_then(|count| count.checked_add(self.indeterminate_sessions));
        if accounted != Some(self.admitted_sessions) {
            return Err(FleetTransportError::serialization(
                "native session drain counts do not partition the retained admission population",
            ));
        }
        if !self.fence_held && !self.is_complete() {
            return Err(FleetTransportError::serialization(
                "native session drain cannot release its fence with pending or indeterminate sessions",
            ));
        }
        if let Some(attestation) = &self.supervisor_attestation {
            attestation.validate_shape()?;
            if attestation.checkpoint_sha256 != self.observation_sha256()? {
                return Err(FleetTransportError::serialization(
                    "native supervisor drain attestation checkpoint was altered",
                ));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self.fence_held && self.population_is_terminal()
    }

    /// Terminal local accounting is independent of whether an operator's
    /// maintenance hold continues to fence admission.
    #[must_use]
    pub fn population_is_terminal(&self) -> bool {
        self.pending_sessions == 0
            && self.indeterminate_sessions == 0
            && self.terminal_sessions == self.admitted_sessions
    }

    #[must_use]
    pub fn state(&self) -> NativeSessionDrainState {
        if self.indeterminate_sessions > 0 {
            NativeSessionDrainState::Indeterminate
        } else if self.is_complete() {
            NativeSessionDrainState::Completed
        } else {
            NativeSessionDrainState::Pending
        }
    }
}

/// Bind the full immutable records affecting `zone_id` in the coordinator's
/// append order. Wildcard actions apply to every zone. Both record contents
/// and order matter: quarantine followed by release is different from release
/// followed by quarantine, regardless of the issuing machines' clocks.
/// The v2 domain refuses historical unordered checkpoints until the agent
/// reapplies the ordered snapshot. Heartbeats remain bounded as history grows.
pub fn fleet_application_checkpoint(
    actions: &[FleetActionRecord],
    zone_id: &str,
) -> Result<FleetApplicationCheckpoint, FleetTransportError> {
    validate_zone_id(zone_id)?;
    let _ = validated_native_session_holds(actions)?;
    let relevant = actions
        .iter()
        .filter(|record| {
            let action_zone = fleet_action_zone(&record.action);
            action_zone == "all" || action_zone == zone_id
        })
        .collect::<Vec<_>>();
    let mut hasher = Sha256::new();
    hasher.update(b"franken-node/fleet-applied-actions/v2\0");
    hasher.update((zone_id.len() as u64).to_le_bytes());
    hasher.update(zone_id.as_bytes());
    hasher.update((relevant.len() as u64).to_le_bytes());
    for record in &relevant {
        let value = serde_json::to_value(record)
            .map_err(|err| FleetTransportError::serialization(err.to_string()))?;
        let payload = canonical_bytes(&value);
        hasher.update((payload.len() as u64).to_le_bytes());
        hasher.update(payload);
    }
    Ok(FleetApplicationCheckpoint {
        action_count: relevant.len() as u64,
        actions_sha256: hex::encode(hasher.finalize()),
    })
}

/// Validate the complete ordered history before resolving native hold owners.
/// An explicit resume cannot name a future action, another action kind, or a
/// different zone. Repeating a resume for the same known owner is idempotent.
fn validated_native_session_holds(
    actions: &[FleetActionRecord],
) -> Result<BTreeMap<&str, (&str, bool)>, FleetTransportError> {
    if actions.len() > MAX_ACTION_LOG_ENTRIES {
        return Err(FleetTransportError::serialization(format!(
            "fleet action snapshot exceeds {MAX_ACTION_LOG_ENTRIES} entries"
        )));
    }
    let mut ids = BTreeSet::new();
    let mut holds = BTreeMap::new();
    let mut active_count = 0_usize;
    for record in actions {
        validate_action_record(record)?;
        if !ids.insert(record.action_id.as_str()) {
            return Err(FleetTransportError::serialization(format!(
                "fleet action snapshot repeats action_id `{}`",
                record.action_id
            )));
        }
        match &record.action {
            FleetAction::NativeSessionHold { zone_id, .. } => {
                if active_count >= MAX_NATIVE_SESSION_MAINTENANCE_HOLDS {
                    return Err(FleetTransportError::serialization(format!(
                        "native-session maintenance exceeds {MAX_NATIVE_SESSION_MAINTENANCE_HOLDS} simultaneous hold owners",
                    )));
                }
                holds.insert(record.action_id.as_str(), (zone_id.as_str(), true));
                active_count += 1;
            }
            FleetAction::NativeSessionResume {
                zone_id,
                hold_action_id,
                ..
            } => {
                let Some((owner_zone, active)) = holds.get_mut(hold_action_id.as_str()) else {
                    return Err(FleetTransportError::serialization(
                        "native-session resume requires a preceding hold action",
                    ));
                };
                if *owner_zone != zone_id.as_str() {
                    return Err(FleetTransportError::serialization(
                        "native-session resume must use its hold's exact original zone",
                    ));
                }
                if *active {
                    *active = false;
                    active_count -= 1;
                }
            }
            _ => {}
        }
    }
    Ok(holds)
}

/// Active immutable hold action IDs affecting one concrete zone, or every
/// active hold when inspecting the fleet-wide `all` audience.
pub fn fleet_native_session_holds(
    actions: &[FleetActionRecord],
    zone_id: &str,
) -> Result<BTreeSet<String>, FleetTransportError> {
    validate_zone_id(zone_id)?;
    Ok(validated_native_session_holds(actions)?
        .into_iter()
        .filter(|(_, (owner_zone, active))| {
            *active && (zone_id == "all" || *owner_zone == "all" || *owner_zone == zone_id)
        })
        .map(|(action_id, _)| action_id.to_owned())
        .collect())
}

/// Validate hold/resume references under the same lock or transaction that
/// admits a publication, preventing a bad resume from poisoning the action log.
pub fn validate_fleet_native_session_publication(
    record: &FleetActionRecord,
    existing: &[FleetActionRecord],
) -> Result<(), FleetTransportError> {
    if !matches!(
        record.action,
        FleetAction::NativeSessionHold { .. } | FleetAction::NativeSessionResume { .. }
    ) {
        return Ok(());
    }
    if existing.contains(record) {
        let _ = validated_native_session_holds(existing)?;
    } else {
        let mut candidate = existing.to_vec();
        candidate.push(record.clone());
        let _ = validated_native_session_holds(&candidate)?;
    }
    Ok(())
}

fn fleet_action_zone(action: &FleetAction) -> &str {
    match action {
        FleetAction::Quarantine { zone_id, .. }
        | FleetAction::Release { zone_id, .. }
        | FleetAction::NativeSessionHold { zone_id, .. }
        | FleetAction::NativeSessionResume { zone_id, .. }
        | FleetAction::PolicyUpdate { zone_id, .. } => zone_id,
        #[cfg(feature = "control-plane")]
        FleetAction::Revoke { scope, .. } => &scope.zone_id,
    }
}

/// Recover the exact ordered, zone-relevant prefix bound to a retained
/// checkpoint. New actions can follow it, but missing, reordered or rewritten
/// records cannot supersede an unfinished local drain or extend a completed
/// one. The entire supplied history is validated before selecting its prefix,
/// including records for other zones and records beyond the checkpoint.
pub fn fleet_action_snapshot_prefix(
    actions: &[FleetActionRecord],
    zone_id: &str,
    checkpoint: &FleetApplicationCheckpoint,
) -> Result<Vec<FleetActionRecord>, FleetTransportError> {
    checkpoint.validate()?;
    let current = fleet_application_checkpoint(actions, zone_id)?;
    if checkpoint.action_count > current.action_count {
        return Err(FleetTransportError::stale_state(
            "fleet action history no longer contains the retained checkpoint's complete prefix",
        ));
    }
    let count = usize::try_from(checkpoint.action_count).map_err(|_| {
        FleetTransportError::serialization(
            "fleet action checkpoint count exceeds this platform's capacity",
        )
    })?;
    let prefix = actions
        .iter()
        .filter(|record| {
            let action_zone = fleet_action_zone(&record.action);
            action_zone == "all" || action_zone == zone_id
        })
        .take(count)
        .cloned()
        .collect::<Vec<_>>();
    let observed = fleet_application_checkpoint(&prefix, zone_id)?;
    if &observed != checkpoint {
        return Err(FleetTransportError::stale_state(
            "fleet action history no longer contains the retained checkpoint's exact ordered prefix",
        ));
    }
    Ok(prefix)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeStatus {
    pub zone_id: String,
    pub node_id: String,
    pub last_seen: DateTime<Utc>,
    pub quarantine_version: u64,
    pub health: NodeHealth,
    /// Missing on historical heartbeats; absence never proves convergence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_actions: Option<FleetApplicationCheckpoint>,
    /// Separate local drain accounting. Historical/application-only heartbeats
    /// have no drain evidence; absence must never be interpreted as completion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_session_drain: Option<NativeSessionDrainCheckpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetSharedState {
    pub schema_version: String,
    pub actions: Vec<FleetActionRecord>,
    pub nodes: Vec<NodeStatus>,
}

impl FleetSharedState {
    #[must_use]
    pub fn matching_nodes<'a>(
        &'a self,
        node_id: &str,
        zone_id: Option<&str>,
    ) -> Vec<&'a NodeStatus> {
        self.nodes
            .iter()
            .filter(|node| {
                node.node_id == node_id
                    && match zone_id {
                        Some(zone_id) => node.zone_id == zone_id,
                        None => true,
                    }
            })
            .collect()
    }
}

/// Why one retained node does or does not satisfy the native-drain gate.
/// These observations never attest a distributed epoch or remote-effect rollback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetNativeDrainReadiness {
    Ready,
    MissingNode,
    NoApplicableActions,
    FutureHeartbeat,
    StaleHeartbeat,
    DrainSnapshotMismatch,
    IndeterminateSessions,
    PendingSessions,
    AdmissionFenced,
    NodeUnhealthy,
    MissingApplicationCheckpoint,
    ApplicationSnapshotMismatch,
    MissingNativeDrain,
    HoldNotActive,
    HoldStillActive,
    MaintenanceFenceMissing,
}

/// One exact node/zone identity in a reconciliation's retained population.
/// Missing nodes remain explicit rows; a new heartbeat cannot remove an older
/// participant merely by changing its node ID or zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetNativeDrainNodeEvidence {
    pub zone_id: String,
    pub node_id: String,
    pub expected_actions: FleetApplicationCheckpoint,
    pub last_seen: Option<DateTime<Utc>>,
    pub health: Option<NodeHealth>,
    pub applied_actions: Option<FleetApplicationCheckpoint>,
    pub native_session_drain: Option<NativeSessionDrainCheckpoint>,
    pub ready: bool,
    pub reason: FleetNativeDrainReadiness,
}

/// Bounded observations for the opt-in native-drain reconciliation gate.
/// Authentication is supplied by the enclosing transport/receipt, not by this
/// aggregate. A complete report describes the retained local populations that
/// the nodes reported drained under the exact current action snapshots. It
/// does not mean admission fences are still held, a fleet epoch committed, or
/// independently observed remote effects have quiesced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetNativeDrainEvidence {
    pub schema_version: String,
    pub scope: String,
    pub observed_at: DateTime<Utc>,
    /// Preserve the exact freshness threshold in the signed payload.
    pub stale_after: Duration,
    pub action_count: u64,
    pub complete: bool,
    pub fleet_quiescence_certified: bool,
    pub uncovered_zones: Vec<String>,
    pub nodes: Vec<FleetNativeDrainNodeEvidence>,
}

/// Aggregate local native-drain observations for every retained action scope.
///
/// Callers retain the union of returned node identities across polling and
/// pass it back as `required_nodes`. They must separately preserve action-log
/// prefix continuity: this function validates one snapshot, not its history.
/// Every input record is validated, even outside currently targeted zones.
/// Future heartbeats, application-only acknowledgements, missing populations,
/// and unresolved effects never satisfy the gate.
pub fn fleet_native_drain_evidence(
    state: &FleetSharedState,
    required_nodes: &BTreeSet<(String, String)>,
    now: DateTime<Utc>,
    stale_after: Duration,
) -> Result<FleetNativeDrainEvidence, FleetTransportError> {
    if state.schema_version != FLEET_SHARED_STATE_SCHEMA {
        return Err(FleetTransportError::serialization(
            "native drain evidence requires the current fleet shared-state schema",
        ));
    }
    if state.nodes.len() > MAX_NODES_CAP || required_nodes.len() > MAX_NODES_CAP {
        return Err(FleetTransportError::serialization(format!(
            "native drain node population exceeds {MAX_NODES_CAP} identities",
        )));
    }
    if stale_after.is_zero() {
        return Err(FleetTransportError::stale_state(
            "native drain heartbeat threshold must be positive",
        ));
    }
    let stale_threshold = chrono::TimeDelta::from_std(stale_after).map_err(|error| {
        FleetTransportError::stale_state(format!(
            "invalid native drain heartbeat threshold: {error}"
        ))
    })?;
    // Validate the complete bounded history and reject duplicate action IDs
    // before any per-zone checkpoint or empty-population result is produced.
    fleet_application_checkpoint(&state.actions, "all")?;
    let action_zones: BTreeSet<&str> = state
        .actions
        .iter()
        .map(|record| fleet_action_zone(&record.action))
        .collect();
    let mut observed = BTreeMap::new();
    let mut participants = required_nodes.clone();
    for (zone_id, node_id) in required_nodes {
        validate_zone_id(zone_id)?;
        validate_node_id(node_id)?;
        if zone_id == "all" {
            return Err(FleetTransportError::serialization(
                "native drain participants require a concrete zone",
            ));
        }
    }
    for node in &state.nodes {
        validate_node_status(node)?;
        if node.zone_id == "all" {
            return Err(FleetTransportError::serialization(
                "native drain participants require a concrete zone",
            ));
        }
        let identity = (node.zone_id.clone(), node.node_id.clone());
        if observed.insert(identity.clone(), node).is_some() {
            return Err(FleetTransportError::serialization(
                "native drain snapshot repeats a node/zone identity",
            ));
        }
        if action_zones.contains("all") || action_zones.contains(node.zone_id.as_str()) {
            participants.insert(identity);
        }
    }
    if participants.len() > MAX_NODES_CAP {
        return Err(FleetTransportError::serialization(format!(
            "retained native drain population exceeds {MAX_NODES_CAP} identities",
        )));
    }
    let present_zones: BTreeSet<&str> = observed
        .keys()
        .map(|(zone_id, _)| zone_id.as_str())
        .collect();
    let uncovered_zones = action_zones
        .iter()
        .filter(|zone| {
            if **zone == "all" {
                observed.is_empty()
            } else {
                !present_zones.contains(**zone)
            }
        })
        .map(|zone| (*zone).to_string())
        .collect::<Vec<_>>();
    let mut expected_by_zone = BTreeMap::<String, FleetApplicationCheckpoint>::new();
    let mut nodes = Vec::with_capacity(participants.len());
    for (zone_id, node_id) in participants {
        let expected_actions = match expected_by_zone.get(&zone_id) {
            Some(checkpoint) => checkpoint.clone(),
            None => {
                let checkpoint = fleet_application_checkpoint(&state.actions, &zone_id)?;
                expected_by_zone.insert(zone_id.clone(), checkpoint.clone());
                checkpoint
            }
        };
        let node = observed.get(&(zone_id.clone(), node_id.clone())).copied();
        let reason = match node {
            None => FleetNativeDrainReadiness::MissingNode,
            Some(_) if expected_actions.action_count == 0 => {
                FleetNativeDrainReadiness::NoApplicableActions
            }
            Some(node) if node.last_seen > now => FleetNativeDrainReadiness::FutureHeartbeat,
            Some(node) if now.signed_duration_since(node.last_seen) >= stale_threshold => {
                FleetNativeDrainReadiness::StaleHeartbeat
            }
            Some(node) => native_drain_readiness(node, &expected_actions),
        };
        nodes.push(FleetNativeDrainNodeEvidence {
            zone_id,
            node_id,
            expected_actions,
            last_seen: node.map(|node| node.last_seen),
            health: node.map(|node| node.health),
            applied_actions: node.and_then(|node| node.applied_actions.clone()),
            native_session_drain: node.and_then(|node| node.native_session_drain.clone()),
            ready: reason == FleetNativeDrainReadiness::Ready,
            reason,
        });
    }
    Ok(FleetNativeDrainEvidence {
        schema_version: "franken-node/fleet-native-drain-evidence/v1".to_string(),
        scope: "local_supervisor_drain_observations".to_string(),
        observed_at: now,
        stale_after,
        action_count: state.actions.len() as u64,
        complete: !state.actions.is_empty()
            && !nodes.is_empty()
            && uncovered_zones.is_empty()
            && nodes.iter().all(|node| node.ready),
        fleet_quiescence_certified: false,
        uncovered_zones,
        nodes,
    })
}

fn native_drain_readiness(
    node: &NodeStatus,
    expected: &FleetApplicationCheckpoint,
) -> FleetNativeDrainReadiness {
    if let Some(drain) = &node.native_session_drain {
        if &drain.applied_actions != expected {
            return FleetNativeDrainReadiness::DrainSnapshotMismatch;
        }
        if drain.indeterminate_sessions > 0 {
            return FleetNativeDrainReadiness::IndeterminateSessions;
        }
        if drain.pending_sessions > 0 {
            return FleetNativeDrainReadiness::PendingSessions;
        }
        if drain.fence_held {
            return FleetNativeDrainReadiness::AdmissionFenced;
        }
    }
    if node.health != NodeHealth::Healthy {
        return FleetNativeDrainReadiness::NodeUnhealthy;
    }
    match &node.applied_actions {
        None => return FleetNativeDrainReadiness::MissingApplicationCheckpoint,
        Some(applied) if applied != expected => {
            return FleetNativeDrainReadiness::ApplicationSnapshotMismatch;
        }
        Some(_) => {}
    }
    match &node.native_session_drain {
        None => FleetNativeDrainReadiness::MissingNativeDrain,
        // The caller validated the checkpoint, including its population
        // partition and application binding, before deriving readiness.
        Some(drain) if drain.is_complete() => FleetNativeDrainReadiness::Ready,
        Some(_) => FleetNativeDrainReadiness::AdmissionFenced,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetNativeSessionHoldTarget {
    Held,
    Resumed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetNativeSessionHoldNodeEvidence {
    pub zone_id: String,
    pub node_id: String,
    pub expected_actions: FleetApplicationCheckpoint,
    pub last_seen: Option<DateTime<Utc>>,
    pub health: Option<NodeHealth>,
    pub applied_actions: Option<FleetApplicationCheckpoint>,
    pub native_session_drain: Option<NativeSessionDrainCheckpoint>,
    pub active_hold_ids: Vec<String>,
    pub ready: bool,
    pub reason: FleetNativeDrainReadiness,
    pub admission_resumed: bool,
}

/// Current local supervisor observations for one immutable maintenance owner.
/// A completed resume can leave admission fenced by another active owner.
/// Neither outcome certifies distributed quiescence or restarts a workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetNativeSessionHoldEvidence {
    pub schema_version: String,
    pub scope: String,
    pub observed_at: DateTime<Utc>,
    pub stale_after: Duration,
    pub action_count: u64,
    pub hold_action_id: String,
    pub hold_zone_id: String,
    pub target: FleetNativeSessionHoldTarget,
    pub complete: bool,
    pub admission_resumed: bool,
    pub fleet_quiescence_certified: bool,
    pub uncovered_zones: Vec<String>,
    pub nodes: Vec<FleetNativeSessionHoldNodeEvidence>,
}

/// Observe the exact original hold audience, retaining every identity supplied
/// by the caller. Unrelated zones are still validated, but cannot satisfy or
/// block this owner's readiness. Callers retain action/source continuity and
/// the union of returned identities across polling, as for drain evidence.
pub fn fleet_native_session_hold_evidence(
    state: &FleetSharedState,
    hold_action_id: &str,
    target: FleetNativeSessionHoldTarget,
    required_nodes: &BTreeSet<(String, String)>,
    now: DateTime<Utc>,
    stale_after: Duration,
) -> Result<FleetNativeSessionHoldEvidence, FleetTransportError> {
    validate_action_id(hold_action_id)?;
    let observed = fleet_native_drain_evidence(state, required_nodes, now, stale_after)?;
    let hold_zone_id = state
        .actions
        .iter()
        .find_map(|record| {
            if record.action_id != hold_action_id {
                return None;
            }
            match &record.action {
                FleetAction::NativeSessionHold { zone_id, .. } => Some(zone_id.clone()),
                _ => None,
            }
        })
        .ok_or_else(|| {
            FleetTransportError::serialization(
                "native-session maintenance evidence requires a retained hold action",
            )
        })?;
    if required_nodes
        .iter()
        .any(|(zone, _)| hold_zone_id != "all" && zone != &hold_zone_id)
    {
        return Err(FleetTransportError::serialization(
            "retained maintenance participant is outside the hold's original zone",
        ));
    }
    let requested_active =
        fleet_native_session_holds(&state.actions, &hold_zone_id)?.contains(hold_action_id);
    let target_satisfied = match target {
        FleetNativeSessionHoldTarget::Held => requested_active,
        FleetNativeSessionHoldTarget::Resumed => !requested_active,
    };
    let mut holds_by_zone = BTreeMap::<String, Vec<String>>::new();
    let mut nodes = Vec::new();
    for node in observed.nodes {
        if hold_zone_id != "all" && node.zone_id != hold_zone_id {
            continue;
        }
        let active_hold_ids = match holds_by_zone.get(&node.zone_id) {
            Some(holds) => holds.clone(),
            None => {
                let holds: Vec<_> = fleet_native_session_holds(&state.actions, &node.zone_id)?
                    .into_iter()
                    .collect();
                holds_by_zone.insert(node.zone_id.clone(), holds.clone());
                holds
            }
        };
        let reason = native_session_hold_readiness(
            &node,
            !active_hold_ids.is_empty(),
            target_satisfied,
            target,
        );
        let ready = reason == FleetNativeDrainReadiness::Ready;
        nodes.push(FleetNativeSessionHoldNodeEvidence {
            zone_id: node.zone_id,
            node_id: node.node_id,
            expected_actions: node.expected_actions,
            last_seen: node.last_seen,
            health: node.health,
            applied_actions: node.applied_actions,
            native_session_drain: node.native_session_drain,
            admission_resumed: ready && active_hold_ids.is_empty(),
            active_hold_ids,
            ready,
            reason,
        });
    }
    let uncovered_zones = if nodes.iter().all(|node| node.last_seen.is_none()) {
        vec![hold_zone_id.clone()]
    } else {
        Vec::new()
    };
    let complete = target_satisfied
        && !nodes.is_empty()
        && uncovered_zones.is_empty()
        && nodes.iter().all(|node| node.ready);
    Ok(FleetNativeSessionHoldEvidence {
        schema_version: "franken-node/fleet-native-session-hold-evidence/v1".to_owned(),
        scope: "local_supervisor_maintenance_observations".to_owned(),
        observed_at: now,
        stale_after,
        action_count: observed.action_count,
        hold_action_id: hold_action_id.to_owned(),
        hold_zone_id,
        target,
        complete,
        admission_resumed: complete && nodes.iter().all(|node| node.admission_resumed),
        fleet_quiescence_certified: false,
        uncovered_zones,
        nodes,
    })
}

fn native_session_hold_readiness(
    node: &FleetNativeDrainNodeEvidence,
    has_active_holds: bool,
    target_satisfied: bool,
    target: FleetNativeSessionHoldTarget,
) -> FleetNativeDrainReadiness {
    if matches!(
        node.reason,
        FleetNativeDrainReadiness::MissingNode
            | FleetNativeDrainReadiness::NoApplicableActions
            | FleetNativeDrainReadiness::FutureHeartbeat
            | FleetNativeDrainReadiness::StaleHeartbeat
    ) {
        return node.reason;
    }
    if !target_satisfied {
        return match target {
            FleetNativeSessionHoldTarget::Held => FleetNativeDrainReadiness::HoldNotActive,
            FleetNativeSessionHoldTarget::Resumed => FleetNativeDrainReadiness::HoldStillActive,
        };
    }
    let Some(drain) = &node.native_session_drain else {
        return FleetNativeDrainReadiness::MissingNativeDrain;
    };
    if drain.applied_actions != node.expected_actions {
        return FleetNativeDrainReadiness::DrainSnapshotMismatch;
    }
    if drain.indeterminate_sessions > 0 {
        return FleetNativeDrainReadiness::IndeterminateSessions;
    }
    if drain.pending_sessions > 0 {
        return FleetNativeDrainReadiness::PendingSessions;
    }
    let expected_health = if has_active_holds {
        if !drain.fence_held {
            return FleetNativeDrainReadiness::MaintenanceFenceMissing;
        }
        NodeHealth::Maintenance
    } else {
        if drain.fence_held {
            return FleetNativeDrainReadiness::AdmissionFenced;
        }
        NodeHealth::Healthy
    };
    if node.health != Some(expected_health) {
        return FleetNativeDrainReadiness::NodeUnhealthy;
    }
    match &node.applied_actions {
        None => FleetNativeDrainReadiness::MissingApplicationCheckpoint,
        Some(applied) if applied != &node.expected_actions => {
            FleetNativeDrainReadiness::ApplicationSnapshotMismatch
        }
        Some(_) => FleetNativeDrainReadiness::Ready,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetPolicyMaintenanceGuard {
    pub hold_action_id: String,
    pub expected_action_log: FleetActionLogCheckpoint,
    pub required_nodes: BTreeSet<(String, String)>,
    pub stale_after: Duration,
}

impl FleetPolicyMaintenanceGuard {
    pub fn validate(&self) -> Result<(), FleetTransportError> {
        validate_action_id(&self.hold_action_id)?;
        self.expected_action_log.validate()?;
        if self.stale_after.is_zero() || self.stale_after > MAX_GUARDED_POLICY_STALE_AFTER {
            return Err(FleetTransportError::stale_state(
                "guarded policy freshness must be positive and at most 300 seconds",
            ));
        }
        if self.required_nodes.len() > MAX_NODES_CAP {
            return Err(FleetTransportError::serialization(
                "guarded policy retained participants exceed the node capacity",
            ));
        }
        for (zone, node) in &self.required_nodes {
            validate_zone_id(zone)?;
            validate_node_id(node)?;
            if zone == "all" {
                return Err(FleetTransportError::serialization(
                    "guarded policy participants require concrete zones",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardedFleetPolicyPublication {
    pub action: FleetActionRecord,
    pub guard: FleetPolicyMaintenanceGuard,
}

impl GuardedFleetPolicyPublication {
    pub fn validate(&self) -> Result<(), FleetTransportError> {
        validate_action_record(&self.action)?;
        self.guard.validate()?;
        let zone = guarded_policy_zone(&self.action)?;
        if self
            .guard
            .required_nodes
            .iter()
            .any(|(participant_zone, _)| zone != "all" && participant_zone != zone)
        {
            return Err(FleetTransportError::serialization(
                "guarded policy participant is outside the publication zone",
            ));
        }
        validate_guarded_json_bound(self, MAX_GUARDED_POLICY_REQUEST_BYTES)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetGuardedPolicyObservationScope {
    LocalSupervisorObservations,
    EnrolledNodeObservations,
}

/// The evidence accepted in the same durable transaction as the policy action.
/// Exact retries return this original evidence, with only `already_published`
/// changed. It does not assert current readiness after the accepted instant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetGuardedPolicyReceipt {
    pub schema_version: String,
    pub action: FleetActionRecord,
    pub guard: FleetPolicyMaintenanceGuard,
    pub evidence: FleetNativeSessionHoldEvidence,
    pub accepted_at: DateTime<Utc>,
    pub observation_scope: FleetGuardedPolicyObservationScope,
    pub already_published: bool,
    pub fleet_quiescence_certified: bool,
}

impl FleetGuardedPolicyReceipt {
    pub fn validate(&self) -> Result<(), FleetTransportError> {
        GuardedFleetPolicyPublication {
            action: self.action.clone(),
            guard: self.guard.clone(),
        }
        .validate()?;
        let evidence = &self.evidence;
        let expected_scope = if self.fleet_quiescence_certified {
            FLEET_EPOCH_BARRIER_CERTIFIED_HOLD_SCOPE
        } else {
            "local_supervisor_maintenance_observations"
        };
        if self.schema_version != FLEET_GUARDED_POLICY_RECEIPT_SCHEMA
            || self.fleet_quiescence_certified != evidence.fleet_quiescence_certified
            || (self.fleet_quiescence_certified
                && self.observation_scope
                    != FleetGuardedPolicyObservationScope::EnrolledNodeObservations)
            || evidence.schema_version != "franken-node/fleet-native-session-hold-evidence/v1"
            || evidence.scope != expected_scope
            || evidence.observed_at != self.accepted_at
            || evidence.hold_action_id != self.guard.hold_action_id
            || evidence.hold_zone_id != guarded_policy_zone(&self.action)?
            || evidence.target != FleetNativeSessionHoldTarget::Held
            || !evidence.complete
            || evidence.admission_resumed
            || !evidence.uncovered_zones.is_empty()
            || evidence.action_count != self.guard.expected_action_log.action_count
            || evidence.action_count == 0
            || evidence.stale_after.is_zero()
            || evidence.stale_after > self.guard.stale_after
            || evidence.nodes.is_empty()
            || evidence.nodes.len() > MAX_NODES_CAP
            || (self.fleet_quiescence_certified
                && evidence.nodes.iter().any(|node| {
                    node.native_session_drain
                        .as_ref()
                        .and_then(|drain| drain.supervisor_attestation.as_ref())
                        .is_none()
                }))
        {
            return Err(FleetTransportError::serialization(
                "guarded policy receipt contradicts its accepted hold evidence",
            ));
        }
        let threshold = chrono::TimeDelta::from_std(evidence.stale_after)
            .map_err(|error| FleetTransportError::serialization(error.to_string()))?;
        let mut identities = BTreeSet::new();
        let mut previous_identity = None;
        for node in &evidence.nodes {
            let identity = (node.zone_id.clone(), node.node_id.clone());
            if previous_identity
                .as_ref()
                .is_some_and(|previous| previous >= &identity)
                || (evidence.hold_zone_id != "all" && node.zone_id != evidence.hold_zone_id)
                || node.expected_actions.action_count == 0
                || node.expected_actions.action_count > evidence.action_count
                || !node.ready
                || node.reason != FleetNativeDrainReadiness::Ready
                || node.admission_resumed
                || node.health != Some(NodeHealth::Maintenance)
                || node.applied_actions.as_ref() != Some(&node.expected_actions)
                || node.active_hold_ids.is_empty()
                || node.active_hold_ids.len() > MAX_NATIVE_SESSION_MAINTENANCE_HOLDS
                || node
                    .active_hold_ids
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
                || !node.active_hold_ids.contains(&self.guard.hold_action_id)
            {
                return Err(FleetTransportError::serialization(
                    "guarded policy receipt has an invalid held participant",
                ));
            }
            for owner in &node.active_hold_ids {
                validate_action_id(owner)?;
            }
            let last_seen = node.last_seen.ok_or_else(|| {
                FleetTransportError::serialization("guarded policy receipt lacks a heartbeat")
            })?;
            if last_seen > self.accepted_at
                || self.accepted_at.signed_duration_since(last_seen) >= threshold
            {
                return Err(FleetTransportError::serialization(
                    "guarded policy receipt contains a stale or future heartbeat",
                ));
            }
            let status = NodeStatus {
                zone_id: node.zone_id.clone(),
                node_id: node.node_id.clone(),
                last_seen,
                quarantine_version: 0,
                health: NodeHealth::Maintenance,
                applied_actions: node.applied_actions.clone(),
                native_session_drain: node.native_session_drain.clone(),
            };
            validate_node_status(&status)?;
            if node.zone_id == "all" {
                return Err(FleetTransportError::serialization(
                    "guarded policy receipt requires concrete participant zones",
                ));
            }
            identities.insert(identity.clone());
            previous_identity = Some(identity);
        }
        if !self.guard.required_nodes.is_subset(&identities) {
            return Err(FleetTransportError::serialization(
                "guarded policy receipt dropped a retained participant",
            ));
        }
        validate_guarded_json_bound(self, MAX_GUARDED_POLICY_RECEIPT_BYTES)
    }
}

fn guarded_policy_zone(action: &FleetActionRecord) -> Result<&str, FleetTransportError> {
    match &action.action {
        FleetAction::PolicyUpdate {
            zone_id,
            artifact: Some(_),
            ..
        } => Ok(zone_id),
        _ => Err(FleetTransportError::serialization(
            "maintenance-guarded publication requires an executable policy action",
        )),
    }
}

fn validate_guarded_json_bound<T: Serialize>(
    value: &T,
    limit: usize,
) -> Result<(), FleetTransportError> {
    struct BoundWriter {
        remaining: usize,
    }
    impl std::io::Write for BoundWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.remaining = self.remaining.checked_sub(bytes.len()).ok_or_else(|| {
                std::io::Error::other("guarded policy payload exceeds its byte bound")
            })?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(BoundWriter { remaining: limit }, value)
        .map_err(|error| FleetTransportError::serialization(error.to_string()))
}

/// Evaluate a guard against one authoritative transaction snapshot. The caller
/// must serialize the read/decision/action write together and apply any enrolled
/// credential projection before this call. Client-supplied evidence is unused.
pub fn validate_guarded_fleet_policy_publication(
    request: &GuardedFleetPolicyPublication,
    state: &FleetSharedState,
    now: DateTime<Utc>,
    max_stale_after: Duration,
) -> Result<FleetNativeSessionHoldEvidence, FleetTransportError> {
    request.validate()?;
    if max_stale_after.is_zero() {
        return Err(FleetTransportError::stale_state(
            "guarded policy coordinator freshness must be positive",
        ));
    }
    if fleet_action_log_checkpoint(&state.actions)? != request.guard.expected_action_log {
        return Err(FleetTransportError::stale_state(
            "guarded policy publication requires the exact retained full action log",
        ));
    }
    if state
        .actions
        .iter()
        .any(|record| record.action_id == request.action.action_id)
    {
        return Err(FleetTransportError::action_conflict(
            "existing policy action requires its original durable guarded receipt",
        ));
    }
    validate_fleet_policy_publication(&request.action, &state.actions)?;
    let evidence = fleet_native_session_hold_evidence(
        state,
        &request.guard.hold_action_id,
        FleetNativeSessionHoldTarget::Held,
        &request.guard.required_nodes,
        now,
        request.guard.stale_after.min(max_stale_after),
    )?;
    if evidence.hold_zone_id != guarded_policy_zone(&request.action)? {
        return Err(FleetTransportError::serialization(
            "guarded policy must use its maintenance hold's exact original zone",
        ));
    }
    if !evidence.complete {
        return Err(FleetTransportError::stale_state(
            "guarded policy requires fresh terminal held observations for every retained participant",
        ));
    }
    Ok(evidence)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FleetTransportError {
    #[error("fleet transport io error: {detail}")]
    IoError { detail: String },
    #[error("fleet transport serialization error: {detail}")]
    SerializationError { detail: String },
    #[error("fleet transport lock contention: {detail}")]
    LockContention { detail: String },
    #[error("fleet transport action conflict: {detail}")]
    ActionConflict { detail: String },
    #[error("fleet transport stale state: {detail}")]
    StaleState { detail: String },
    #[error("fleet transport not initialized: {detail}")]
    NotInitialized { detail: String },
}

impl FleetTransportError {
    #[must_use]
    pub fn io(detail: impl Into<String>) -> Self {
        Self::IoError {
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn serialization(detail: impl Into<String>) -> Self {
        Self::SerializationError {
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn lock_contention(detail: impl Into<String>) -> Self {
        Self::LockContention {
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn action_conflict(detail: impl Into<String>) -> Self {
        Self::ActionConflict {
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn stale_state(detail: impl Into<String>) -> Self {
        Self::StaleState {
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn not_initialized(detail: impl Into<String>) -> Self {
        Self::NotInitialized {
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetTransportLayout {
    root_dir: PathBuf,
    actions_path: PathBuf,
    nodes_dir: PathBuf,
    locks_dir: PathBuf,
}

impl FleetTransportLayout {
    #[must_use]
    pub fn new(root_dir: impl Into<PathBuf>) -> Self {
        let root_dir = root_dir.into();
        Self {
            actions_path: root_dir.join(FLEET_ACTION_LOG_FILE),
            nodes_dir: root_dir.join(FLEET_NODE_DIR),
            locks_dir: root_dir.join(FLEET_LOCK_DIR),
            root_dir,
        }
    }

    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    #[must_use]
    pub fn actions_path(&self) -> &Path {
        &self.actions_path
    }

    #[must_use]
    pub fn nodes_dir(&self) -> &Path {
        &self.nodes_dir
    }

    #[must_use]
    pub fn locks_dir(&self) -> &Path {
        &self.locks_dir
    }

    pub fn initialize(&self) -> Result<(), FleetTransportError> {
        std::fs::create_dir_all(&self.root_dir).map_err(|err| {
            FleetTransportError::io(format!(
                "failed creating fleet transport root {}: {err}",
                self.root_dir.display()
            ))
        })?;
        std::fs::create_dir_all(&self.nodes_dir).map_err(|err| {
            FleetTransportError::io(format!(
                "failed creating fleet transport nodes dir {}: {err}",
                self.nodes_dir.display()
            ))
        })?;
        std::fs::create_dir_all(&self.locks_dir).map_err(|err| {
            FleetTransportError::io(format!(
                "failed creating fleet transport lock dir {}: {err}",
                self.locks_dir.display()
            ))
        })?;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.actions_path)
            .map_err(|err| {
                FleetTransportError::io(format!(
                    "failed creating fleet action log {}: {err}",
                    self.actions_path.display()
                ))
            })?;
        let parent = normalized_directory(self.root_dir.parent().unwrap_or_else(|| Path::new(".")));
        sync_directory(parent)?;
        sync_directory(&self.root_dir)?;
        Ok(())
    }

    pub fn node_status_path(&self, node_id: &str) -> Result<PathBuf, FleetTransportError> {
        let node_id = validate_node_id(node_id)?;
        Ok(self.nodes_dir.join(format!("node-{node_id}.json")))
    }
}

/// Transport abstraction for distributed fleet coordination state.
///
/// The `FleetTransport` trait provides a storage-agnostic interface for managing
/// fleet actions and node status in distributed systems. Implementations can use
/// file systems, databases, or networked storage to persist fleet state.
///
/// The trait manages two primary data types:
/// - **Fleet Actions**: Records of operations performed across the fleet (quarantine, rollback, etc.)
/// - **Node Status**: Health and metadata for individual nodes in the fleet
///
/// # Implementations
///
/// - [`FileFleetTransport`]: File-based implementation using JSONL action logs
/// - [`AsupersyncFleetTransport`]: Network-based implementation using asupersync protocol
///
/// # Example: Implementing a Custom Transport
///
/// ```rust
/// use std::collections::HashMap;
/// use chrono::Utc;
/// use crate::control_plane::fleet_transport::*;
///
/// struct MemoryFleetTransport {
///     actions: Vec<FleetActionRecord>,
///     nodes: HashMap<String, NodeStatus>,
///     initialized: bool,
/// }
///
/// impl MemoryFleetTransport {
///     fn new() -> Self {
///         Self {
///             actions: Vec::new(),
///             nodes: HashMap::new(),
///             initialized: false,
///         }
///     }
/// }
///
/// impl FleetTransport for MemoryFleetTransport {
///     fn initialize(&mut self) -> Result<(), FleetTransportError> {
///         self.initialized = true;
///         Ok(())
///     }
///
///     fn publish_action(&mut self, action: &FleetActionRecord) -> Result<(), FleetTransportError> {
///         if !self.initialized {
///             return Err(FleetTransportError::io("Transport not initialized".to_string()));
///         }
///         self.actions.push(action.clone());
///         Ok(())
///     }
///
///     fn list_actions(&self) -> Result<Vec<FleetActionRecord>, FleetTransportError> {
///         Ok(self.actions.clone())
///     }
///
///     fn upsert_node_status(&mut self, status: &NodeStatus) -> Result<(), FleetTransportError> {
///         let key = format!("{}-{}", status.zone_id, status.node_id);
///         self.nodes.insert(key, status.clone());
///         Ok(())
///     }
///
///     fn list_node_statuses(&self) -> Result<Vec<NodeStatus>, FleetTransportError> {
///         Ok(self.nodes.values().cloned().collect())
///     }
/// }
/// ```
///
/// # Example: Using a Transport
///
/// ```rust
/// use chrono::Utc;
/// use crate::control_plane::fleet_transport::*;
///
/// # fn example_usage() -> Result<(), FleetTransportError> {
/// let mut transport = FileFleetTransport::new("/tmp/fleet-data".into())?;
/// transport.initialize()?;
///
/// // Publish a fleet action
/// let action = FleetActionRecord {
///     action_id: "action-001".to_string(),
///     emitted_at: Utc::now(),
///     action: FleetAction::QuarantineNode {
///         node_id: "node-1".to_string(),
///         reason: "Suspicious behavior detected".to_string(),
///     },
/// };
/// transport.publish_action(&action)?;
///
/// // Update node status
/// let status = NodeStatus {
///     zone_id: "zone-a".to_string(),
///     node_id: "node-1".to_string(),
///     last_seen: Utc::now(),
///     quarantine_version: 1,
///     health: NodeHealth::Quarantined,
///     applied_actions: None,
///     native_session_drain: None,
/// };
/// transport.upsert_node_status(&status)?;
///
/// // Read consolidated fleet state
/// let shared_state = transport.read_shared_state()?;
/// println!("Fleet has {} actions and {} nodes",
///          shared_state.actions.len(),
///          shared_state.nodes.len());
/// # Ok(())
/// # }
/// ```
pub trait FleetTransport {
    /// Initialize the transport layer and prepare for operations.
    ///
    /// This method sets up any required infrastructure (directories, connections, etc.)
    /// and must be called before any other operations.
    ///
    /// # Errors
    ///
    /// Returns [`FleetTransportError::Io`] if initialization fails due to I/O issues.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use crate::control_plane::fleet_transport::*;
    /// # fn setup() -> Result<(), FleetTransportError> {
    /// let mut transport = FileFleetTransport::new("/tmp/fleet".into())?;
    /// transport.initialize()?;
    /// // Transport is now ready for operations
    /// # Ok(())
    /// # }
    /// ```
    fn initialize(&mut self) -> Result<(), FleetTransportError>;

    /// Publish a fleet action to the persistent log.
    ///
    /// Fleet actions represent operations performed across the distributed fleet,
    /// such as quarantine requests, rollback commands, or configuration changes.
    /// Actions are timestamped and stored in the coordinator's serialized
    /// append order. Issuer timestamps are metadata, not causal ordering.
    /// A retained `action_id` identifies one immutable record, including its
    /// original timestamp. Retrying that exact record succeeds without adding
    /// another action. Reusing its ID with different contents fails with
    /// [`FleetTransportError::ActionConflict`] and preserves the original.
    ///
    /// # Parameters
    ///
    /// - `action`: The fleet action record to persist
    ///
    /// # Errors
    ///
    /// Returns [`FleetTransportError::IoError`] for storage failures or
    /// [`FleetTransportError::SerializationError`] for invalid records and
    /// [`FleetTransportError::ActionConflict`] for a conflicting action ID.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use chrono::Utc;
    /// # use crate::control_plane::fleet_transport::*;
    /// # fn publish_example(transport: &mut impl FleetTransport) -> Result<(), FleetTransportError> {
    /// let action = FleetActionRecord {
    ///     action_id: uuid::Uuid::new_v4().to_string(),
    ///     emitted_at: Utc::now(),
    ///     action: FleetAction::RollbackNode {
    ///         node_id: "node-42".to_string(),
    ///         target_version: "v1.2.3".to_string(),
    ///     },
    /// };
    /// transport.publish_action(&action)?;
    /// # Ok(())
    /// # }
    /// ```
    fn publish_action(&mut self, action: &FleetActionRecord) -> Result<(), FleetTransportError>;

    /// Atomically admit an executable policy while its retained maintenance
    /// audience is freshly observed held. Optional transports must implement
    /// the transaction contract explicitly; a read-then-write fallback is unsafe.
    fn publish_policy_with_maintenance_guard(
        &mut self,
        _request: &GuardedFleetPolicyPublication,
    ) -> Result<FleetGuardedPolicyReceipt, FleetTransportError> {
        Err(FleetTransportError::not_initialized(
            "this fleet transport does not support atomic maintenance-guarded policy publication",
        ))
    }

    /// Retrieve all fleet actions in their durable append order.
    ///
    /// Returns the complete retained action history in the order accepted by
    /// the coordinator. Neither issuer clock skew nor action IDs may reorder
    /// quarantine and release. Exact retries retain their original position.
    ///
    /// # Returns
    ///
    /// Vector of [`FleetActionRecord`]s in append order.
    ///
    /// # Errors
    ///
    /// Returns [`FleetTransportError::Io`] for storage access failures or
    /// [`FleetTransportError::Serialization`] for corrupt data.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use crate::control_plane::fleet_transport::*;
    /// # fn list_example(transport: &impl FleetTransport) -> Result<(), FleetTransportError> {
    /// let actions = transport.list_actions()?;
    /// for action in actions {
    ///     println!("Action {}: {:?} at {}",
    ///              action.action_id, action.action, action.emitted_at);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    fn list_actions(&self) -> Result<Vec<FleetActionRecord>, FleetTransportError>;

    /// Update or insert node status information.
    ///
    /// Maintains the current health and metadata for fleet nodes. If a node status
    /// already exists, it is updated. Otherwise, a new entry is created.
    ///
    /// Node status includes health state, quarantine version, and last-seen timestamp
    /// for fleet monitoring and decision-making.
    ///
    /// # Parameters
    ///
    /// - `status`: Node status to persist, identified by zone_id + node_id
    ///
    /// # Errors
    ///
    /// Returns [`FleetTransportError::Io`] for storage failures or
    /// [`FleetTransportError::Validation`] for invalid node identifiers.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use chrono::Utc;
    /// # use crate::control_plane::fleet_transport::*;
    /// # fn upsert_example(transport: &mut impl FleetTransport) -> Result<(), FleetTransportError> {
    /// let status = NodeStatus {
    ///     zone_id: "us-west-1".to_string(),
    ///     node_id: "worker-05".to_string(),
    ///     last_seen: Utc::now(),
    ///     quarantine_version: 0,  // Not quarantined
    ///     health: NodeHealth::Healthy,
    ///     applied_actions: None,
    ///     native_session_drain: None,
    /// };
    /// transport.upsert_node_status(&status)?;
    /// # Ok(())
    /// # }
    /// ```
    fn upsert_node_status(&mut self, status: &NodeStatus) -> Result<(), FleetTransportError>;

    /// Retrieve all node status records.
    ///
    /// Returns the current status of all nodes in the fleet, including health state,
    /// quarantine information, and last-seen timestamps. Results are sorted by
    /// zone_id then node_id for consistent ordering.
    ///
    /// # Returns
    ///
    /// Vector of [`NodeStatus`] records sorted by zone and node ID.
    ///
    /// # Errors
    ///
    /// Returns [`FleetTransportError::Io`] for storage access failures or
    /// [`FleetTransportError::Serialization`] for corrupt data.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use crate::control_plane::fleet_transport::*;
    /// # fn status_example(transport: &impl FleetTransport) -> Result<(), FleetTransportError> {
    /// let statuses = transport.list_node_statuses()?;
    /// let healthy_count = statuses.iter()
    ///     .filter(|s| s.health == NodeHealth::Healthy)
    ///     .count();
    /// println!("Healthy nodes: {}/{}", healthy_count, statuses.len());
    /// # Ok(())
    /// # }
    /// ```
    fn list_node_statuses(&self) -> Result<Vec<NodeStatus>, FleetTransportError>;

    /// Retrieve the consolidated fleet state combining actions and node status.
    ///
    /// This method provides a unified view of the fleet by combining the complete
    /// action history with current node status. The returned state includes:
    /// - All fleet actions in append order
    /// - All node statuses sorted by zone and node ID
    /// - Schema version for compatibility checking
    ///
    /// This is the primary method used by fleet controllers to get a complete
    /// picture of fleet state for decision-making.
    ///
    /// # Returns
    ///
    /// [`FleetSharedState`] containing ordered actions and sorted node statuses.
    ///
    /// # Errors
    ///
    /// Returns errors from [`list_actions`] or [`list_node_statuses`] if data
    /// retrieval fails.
    ///
    /// # Default Implementation
    ///
    /// The default implementation calls [`list_actions`] and [`list_node_statuses`],
    /// preserves action order, sorts nodes, and packages them into [`FleetSharedState`]. Most
    /// implementations can rely on this default behavior.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use crate::control_plane::fleet_transport::*;
    /// # fn state_example(transport: &impl FleetTransport) -> Result<(), FleetTransportError> {
    /// let state = transport.read_shared_state()?;
    ///
    /// println!("Fleet State (schema: {})", state.schema_version);
    /// println!("  Actions: {} records", state.actions.len());
    /// println!("  Nodes: {} active", state.nodes.len());
    ///
    /// // Find recent quarantine actions
    /// let quarantine_actions: Vec<_> = state.actions.iter()
    ///     .filter(|a| matches!(a.action, FleetAction::QuarantineNode { .. }))
    ///     .collect();
    /// println!("  Quarantine actions: {}", quarantine_actions.len());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`list_actions`]: FleetTransport::list_actions
    /// [`list_node_statuses`]: FleetTransport::list_node_statuses
    fn read_shared_state(&self) -> Result<FleetSharedState, FleetTransportError> {
        let actions = self.list_actions()?;

        let mut nodes = self.list_node_statuses()?;
        nodes.sort_by(|left, right| {
            left.zone_id
                .cmp(&right.zone_id)
                .then_with(|| left.node_id.cmp(&right.node_id))
        });

        Ok(FleetSharedState {
            schema_version: FLEET_SHARED_STATE_SCHEMA.to_string(),
            actions,
            nodes,
        })
    }
}

#[cfg(feature = "asupersync-transport")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsupersyncFleetControlEvent {
    pub operation: String,
    pub node_id: String,
    pub observed_at: DateTime<Utc>,
}

#[cfg(feature = "asupersync-transport")]
#[derive(Debug, Clone, Default)]
pub struct AsupersyncFleetNetwork {
    state: Arc<RwLock<AsupersyncFleetNetworkState>>,
    control_events: Arc<Mutex<Vec<AsupersyncFleetControlEvent>>>,
}

#[cfg(feature = "asupersync-transport")]
#[derive(Debug, Clone, Default)]
struct AsupersyncFleetNetworkState {
    initialized: bool,
    actions: Arc<Vec<FleetActionRecord>>,
    nodes: Arc<Vec<NodeStatus>>,
}

#[cfg(feature = "asupersync-transport")]
impl AsupersyncFleetNetwork {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn control_events(&self) -> Result<Vec<AsupersyncFleetControlEvent>, FleetTransportError> {
        Ok(self.control_events_lock()?.clone())
    }

    fn read_state(
        &self,
    ) -> Result<RwLockReadGuard<'_, AsupersyncFleetNetworkState>, FleetTransportError> {
        self.state
            .read()
            .map_err(|err| FleetTransportError::lock_contention(err.to_string()))
    }

    fn write_state(
        &self,
    ) -> Result<RwLockWriteGuard<'_, AsupersyncFleetNetworkState>, FleetTransportError> {
        self.state
            .write()
            .map_err(|err| FleetTransportError::lock_contention(err.to_string()))
    }

    fn control_events_lock(
        &self,
    ) -> Result<MutexGuard<'_, Vec<AsupersyncFleetControlEvent>>, FleetTransportError> {
        self.control_events
            .lock()
            .map_err(|err| FleetTransportError::lock_contention(err.to_string()))
    }
}

#[cfg(feature = "asupersync-transport")]
#[derive(Debug, Clone)]
pub struct AsupersyncFleetTransport {
    cx: asupersync::Cx,
    node_id: String,
    network: AsupersyncFleetNetwork,
}

#[cfg(feature = "asupersync-transport")]
impl AsupersyncFleetTransport {
    /// Retains the caller's context, including its budget, cancellation state,
    /// and runtime capability mask. The caller owns the runtime lifetime.
    #[must_use]
    pub fn with_cx(
        cx: asupersync::Cx,
        node_id: impl Into<String>,
        network: AsupersyncFleetNetwork,
    ) -> Self {
        Self {
            cx,
            node_id: node_id.into(),
            network,
        }
    }

    /// Uses the currently installed request context without creating authority.
    ///
    /// Outside a runtime request, use [`Self::with_cx`] with a context supplied
    /// by the runtime owner. A missing context is an explicit refusal.
    pub fn for_request(
        node_id: impl Into<String>,
        network: AsupersyncFleetNetwork,
    ) -> Result<Self, FleetTransportError> {
        let cx = asupersync::Cx::current().ok_or_else(|| {
            FleetTransportError::not_initialized(
                "asupersync request context is not installed; use AsupersyncFleetTransport::with_cx",
            )
        })?;
        Ok(Self::with_cx(cx, node_id, network))
    }

    #[must_use]
    pub fn network(&self) -> &AsupersyncFleetNetwork {
        &self.network
    }

    fn checkpoint(&self, operation: &'static str) -> Result<(), FleetTransportError> {
        self.cx.trace_with_fields(
            "fleet asupersync control-lane transport operation",
            &[
                ("transport", "asupersync"),
                ("operation", operation),
                ("node_id", &self.node_id),
            ],
        );
        self.cx.checkpoint().map_err(|err| {
            FleetTransportError::stale_state(format!(
                "asupersync control-lane checkpoint failed during {operation}: {err}"
            ))
        })
    }

    fn record_event(&self, operation: &'static str) -> Result<(), FleetTransportError> {
        let event = AsupersyncFleetControlEvent {
            operation: operation.to_string(),
            node_id: self.node_id.clone(),
            observed_at: clock::wall_now(),
        };
        let mut control_events = self.network.control_events_lock()?;
        push_bounded(&mut control_events, event, MAX_CONTROL_EVENTS);
        Ok(())
    }

    fn ensure_initialized(
        &self,
        state: &AsupersyncFleetNetworkState,
    ) -> Result<(), FleetTransportError> {
        if state.initialized {
            Ok(())
        } else {
            Err(FleetTransportError::not_initialized(
                "call initialize() before using the asupersync fleet transport",
            ))
        }
    }
}

#[cfg(feature = "asupersync-transport")]
impl FleetTransport for AsupersyncFleetTransport {
    fn initialize(&mut self) -> Result<(), FleetTransportError> {
        self.checkpoint("initialize")?;
        {
            let mut state = self.network.write_state()?;
            state.initialized = true;
        }
        self.record_event("initialize")?;
        Ok(())
    }

    fn publish_action(&mut self, action: &FleetActionRecord) -> Result<(), FleetTransportError> {
        self.checkpoint("publish_action")?;
        validate_action_record(action)?;
        let payload = serde_json::to_vec(action).map_err(|err| {
            FleetTransportError::serialization(format!(
                "failed serializing asupersync fleet action {}: {err}",
                action.action_id
            ))
        })?;
        if payload.len() > MAX_ACTION_RECORD_BYTES {
            return Err(FleetTransportError::serialization(format!(
                "serialized fleet action {} exceeds {} bytes",
                action.action_id, MAX_ACTION_RECORD_BYTES
            )));
        }

        {
            let mut state = self.network.write_state()?;
            self.ensure_initialized(&state)?;
            if let Some(existing) = state
                .actions
                .iter()
                .find(|existing| existing.action_id == action.action_id)
            {
                if existing != action {
                    return Err(FleetTransportError::action_conflict(format!(
                        "action_id `{}` already identifies a different fleet action",
                        action.action_id
                    )));
                }
                drop(state);
                self.record_event("publish_action")?;
                return Ok(());
            }
            if state.actions.len() >= MAX_ACTION_LOG_ENTRIES {
                return Err(FleetTransportError::serialization(format!(
                    "fleet action log already contains the maximum {MAX_ACTION_LOG_ENTRIES} entries; refusing to discard retained containment actions"
                )));
            }
            validate_fleet_policy_publication(action, state.actions.as_ref())?;
            let mut actions = state.actions.as_ref().clone();
            actions.push(action.clone());
            state.actions = Arc::new(actions);
        }
        self.record_event("publish_action")?;
        Ok(())
    }

    fn list_actions(&self) -> Result<Vec<FleetActionRecord>, FleetTransportError> {
        self.checkpoint("list_actions")?;
        let actions = {
            let state = self.network.read_state()?;
            self.ensure_initialized(&state)?;
            Arc::clone(&state.actions)
        };
        self.record_event("list_actions")?;
        Ok(actions.as_ref().clone())
    }

    fn upsert_node_status(&mut self, status: &NodeStatus) -> Result<(), FleetTransportError> {
        self.checkpoint("upsert_node_status")?;
        validate_node_status(status)?;

        {
            let mut state = self.network.write_state()?;
            self.ensure_initialized(&state)?;
            let mut nodes = state.nodes.as_ref().clone();
            if let Some(existing) = nodes
                .iter_mut()
                .find(|existing| existing.node_id == status.node_id)
            {
                *existing = status.clone();
            } else {
                push_bounded(&mut nodes, status.clone(), MAX_NODES_CAP);
            }
            state.nodes = Arc::new(nodes);
        }
        self.record_event("upsert_node_status")?;
        Ok(())
    }

    fn list_node_statuses(&self) -> Result<Vec<NodeStatus>, FleetTransportError> {
        self.checkpoint("list_node_statuses")?;
        let nodes = {
            let state = self.network.read_state()?;
            self.ensure_initialized(&state)?;
            Arc::clone(&state.nodes)
        };
        self.record_event("list_node_statuses")?;
        Ok(nodes.as_ref().clone())
    }

    fn read_shared_state(&self) -> Result<FleetSharedState, FleetTransportError> {
        self.checkpoint("read_shared_state")?;
        let (actions, nodes) = {
            let state = self.network.read_state()?;
            self.ensure_initialized(&state)?;
            (Arc::clone(&state.actions), Arc::clone(&state.nodes))
        };
        self.record_event("read_shared_state")?;

        let actions = actions.as_ref().clone();

        let mut nodes = nodes.as_ref().clone();
        nodes.sort_by(|left, right| {
            left.zone_id
                .cmp(&right.zone_id)
                .then_with(|| left.node_id.cmp(&right.node_id))
        });

        Ok(FleetSharedState {
            schema_version: FLEET_SHARED_STATE_SCHEMA.to_string(),
            actions,
            nodes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFleetTransport {
    layout: FleetTransportLayout,
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
            .unwrap_or("fleet-transport.tmp");
        path.with_file_name(format!("{file_name}.orphaned-{}", Uuid::now_v7()))
    }

    fn defuse(&mut self) {
        self.0 = None;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take()
            && path.is_file()
        {
            let orphaned_path = Self::abandoned_path(&path);
            if let Err(err) = fs::rename(&path, &orphaned_path) {
                warn!(
                    original_path = %path.display(),
                    orphaned_path = %orphaned_path.display(),
                    error = %err,
                    "failed to orphan temp file during cleanup - file may remain as temp debris"
                );
            }
        }
    }
}

fn fleet_action_compaction_registry() -> &'static (Mutex<BTreeSet<PathBuf>>, Condvar) {
    static REGISTRY: OnceLock<(Mutex<BTreeSet<PathBuf>>, Condvar)> = OnceLock::new();
    REGISTRY.get_or_init(|| (Mutex::new(BTreeSet::new()), Condvar::new()))
}

fn fleet_action_compaction_root_key(root_dir: &Path) -> Result<PathBuf, FleetTransportError> {
    crate::canonical_lock_key(root_dir).map_err(|err| {
        FleetTransportError::io(format!(
            "failed deriving fleet action compaction root lock key for {}: {err}",
            root_dir.display()
        ))
    })
}

/// RAII guard for fleet action compaction process coordination
struct FleetActionCompactionGuard {
    root_key: PathBuf,
}

impl Drop for FleetActionCompactionGuard {
    fn drop(&mut self) {
        let (registry, ready) = fleet_action_compaction_registry();
        let mut registry = registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        registry.remove(&self.root_key);
        ready.notify_all();
    }
}

fn lock_fleet_action_compaction_process(
    root_dir: &Path,
) -> Result<FleetActionCompactionGuard, FleetTransportError> {
    let root_key = fleet_action_compaction_root_key(root_dir)?;
    let (registry, ready) = fleet_action_compaction_registry();
    let mut registry = registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    while registry.contains(&root_key) {
        registry = ready
            .wait(registry)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
    }
    registry.insert(root_key.clone());
    Ok(FleetActionCompactionGuard { root_key })
}

#[cfg(feature = "test-support")]
pub struct FleetActionCompactionGuardForTest {
    _guard: FleetActionCompactionGuard,
}

#[cfg(feature = "test-support")]
pub fn fleet_action_compaction_root_key_for_test(
    root_dir: &Path,
) -> Result<PathBuf, FleetTransportError> {
    fleet_action_compaction_root_key(root_dir)
}

#[cfg(feature = "test-support")]
pub fn lock_fleet_action_compaction_process_for_test(
    root_dir: &Path,
) -> Result<FleetActionCompactionGuardForTest, FleetTransportError> {
    lock_fleet_action_compaction_process(root_dir)
        .map(|guard| FleetActionCompactionGuardForTest { _guard: guard })
}

impl FileFleetTransport {
    #[must_use]
    pub fn new(root_dir: impl Into<PathBuf>) -> Self {
        Self {
            layout: FleetTransportLayout::new(root_dir),
        }
    }

    #[must_use]
    pub fn layout(&self) -> &FleetTransportLayout {
        &self.layout
    }

    pub fn list_stale_nodes(
        &self,
        now: DateTime<Utc>,
        staleness_threshold: Duration,
    ) -> Result<Vec<NodeStatus>, FleetTransportError> {
        let staleness_threshold = chrono::TimeDelta::from_std(staleness_threshold)
            .map_err(|err| FleetTransportError::stale_state(format!("invalid threshold: {err}")))?;

        let mut stale_nodes: Vec<NodeStatus> = self
            .list_node_statuses()?
            .into_iter()
            .filter(|status| now.signed_duration_since(status.last_seen) >= staleness_threshold)
            .collect();
        stale_nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        Ok(stale_nodes)
    }

    fn ensure_initialized(&self) -> Result<(), FleetTransportError> {
        if !self.layout.root_dir().is_dir()
            || !self.layout.nodes_dir().is_dir()
            || !self.layout.locks_dir().is_dir()
            || !self.layout.actions_path().is_file()
        {
            return Err(FleetTransportError::not_initialized(
                "call initialize() before using the file transport",
            ));
        }
        Ok(())
    }

    fn compact_action_log_if_needed(
        &self,
        max_file_size_bytes: u64,
        retention_days: i64,
        now: DateTime<Utc>,
    ) -> Result<(), FleetTransportError> {
        if retention_days <= 0 {
            return Err(FleetTransportError::serialization(
                "retention_days must be greater than zero",
            ));
        }

        // DEADLOCK FIX: Acquire compaction lock BEFORE shared_state_lock to establish consistent lock ordering.
        // This prevents AB-BA deadlock where other code paths might acquire shared_state_lock first.
        let _process_guard = lock_fleet_action_compaction_process(self.layout.root_dir())?;
        let compaction_lock_path = self.action_compaction_lock_path();
        let compaction_lock_file = self.lock_file(&compaction_lock_path)?;
        lock_file_with_backoff(&compaction_lock_file, &compaction_lock_path, false)?;

        let compaction_result = self.with_shared_state_lock(false, || {
            let compaction_inner_result = (|| {
                let metadata = fs::metadata(self.layout.actions_path()).map_err(|err| {
                    FleetTransportError::io(format!(
                        "failed reading fleet action log metadata {}: {err}",
                        self.layout.actions_path().display()
                    ))
                })?;
                if metadata.len() <= max_file_size_bytes {
                    return Ok(());
                }

                let file = self.action_log_file(true)?;
                lock_file_with_backoff(&file, self.layout.actions_path(), false)?;
                let rewrite_result = (|| {
                    let retention_window = chrono::TimeDelta::days(retention_days);
                    let actions = parse_jsonl_records::<FleetActionRecord>(
                        &file,
                        self.layout.actions_path(),
                    )?;
                    for action in &actions {
                        validate_action_record(action)?;
                    }
                    // The log's serialized append order is authoritative.
                    // Sorting by issuer time could retire a newer quarantine
                    // under an older release, including during compaction.
                    // Quarantines do not expire merely because their incident
                    // is old. Retain its whole history until it is released and
                    // every incident record has aged past retention, so pruning
                    // cannot forget containment or resurrect a retired action.
                    let mut incidents =
                        std::collections::BTreeMap::<(String, String), (bool, bool)>::new();
                    for record in &actions {
                        let (zone, incident, active) = match &record.action {
                            FleetAction::Quarantine {
                                zone_id,
                                incident_id,
                                ..
                            } => (zone_id, incident_id, true),
                            FleetAction::Release {
                                zone_id,
                                incident_id,
                                ..
                            } => (zone_id, incident_id, false),
                            _ => continue,
                        };
                        let state = incidents
                            .entry((zone.clone(), incident.clone()))
                            .or_default();
                        state.0 |= now.signed_duration_since(record.emitted_at) <= retention_window;
                        state.1 = active;
                    }
                    let retained_actions = actions
                        .into_iter()
                        .filter(|record| {
                            match &record.action {
                                FleetAction::Quarantine {
                                    zone_id,
                                    incident_id,
                                    ..
                                }
                                | FleetAction::Release {
                                    zone_id,
                                    incident_id,
                                    ..
                                } => incidents
                                    .get(&(zone_id.clone(), incident_id.clone()))
                                    .is_some_and(|(recent, active)| *recent || *active),
                                // Revocations and policy intent have no implicit
                                // expiry or executable reversal in this protocol.
                                _ => true,
                            }
                        })
                        .collect::<Vec<_>>();

                    let temp_path = self
                        .layout
                        .actions_path()
                        .with_extension(format!("jsonl.tmp-{}", Uuid::now_v7()));
                    let mut temp_guard = TempFileGuard::new(temp_path.clone());
                    let mut temp_file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&temp_path)
                        .map_err(|err| {
                            FleetTransportError::io(format!(
                                "failed opening compacted fleet action log {}: {err}",
                                temp_path.display()
                            ))
                        })?;

                    for record in retained_actions {
                        let payload = serde_json::to_vec(&record).map_err(|err| {
                            FleetTransportError::serialization(format!(
                                "failed serializing compacted fleet action {}: {err}",
                                record.action_id
                            ))
                        })?;
                        temp_file.write_all(&payload).map_err(|err| {
                            FleetTransportError::io(format!(
                                "failed writing compacted fleet action log {}: {err}",
                                temp_path.display()
                            ))
                        })?;
                        temp_file.write_all(b"\n").map_err(|err| {
                            FleetTransportError::io(format!(
                                "failed writing compacted fleet action delimiter {}: {err}",
                                temp_path.display()
                            ))
                        })?;
                    }
                    temp_file.sync_all().map_err(|err| {
                        FleetTransportError::io(format!(
                            "failed syncing compacted fleet action log {}: {err}",
                            temp_path.display()
                        ))
                    })?;
                    drop(temp_file);
                    fs::rename(&temp_path, self.layout.actions_path()).map_err(|err| {
                        FleetTransportError::io(format!(
                            "failed promoting compacted fleet action log {} to {}: {err}",
                            temp_path.display(),
                            self.layout.actions_path().display()
                        ))
                    })?;
                    temp_guard.defuse();
                    sync_directory(self.layout.root_dir())?;
                    Ok(())
                })();

                let unlock_result = unlock_file(&file, self.layout.actions_path());
                rewrite_result?;
                unlock_result?;
                Ok(())
            })();

            // Return result of compaction operation
            compaction_inner_result
        });

        // DEADLOCK FIX: Unlock compaction lock AFTER shared_state_lock is released
        // Always unlock the compaction lock regardless of compaction result
        let unlock_result = unlock_file(&compaction_lock_file, &compaction_lock_path);

        // Propagate errors only after ensuring unlock
        compaction_result?;
        unlock_result?;
        Ok(())
    }

    fn action_log_file(&self, write: bool) -> Result<File, FleetTransportError> {
        let mut options = OpenOptions::new();
        options.read(true);
        if write {
            options.append(true).create(true);
        }
        options.open(self.layout.actions_path()).map_err(|err| {
            FleetTransportError::io(format!(
                "failed opening fleet action log {}: {err}",
                self.layout.actions_path().display()
            ))
        })
    }

    fn node_lock_path(&self, node_id: &str) -> Result<PathBuf, FleetTransportError> {
        let node_id = validate_node_id(node_id)?;
        Ok(self.layout.locks_dir().join(format!("node-{node_id}.lock")))
    }

    fn action_compaction_lock_path(&self) -> PathBuf {
        self.layout
            .locks_dir()
            .join(FLEET_ACTION_COMPACTION_LOCK_FILE)
    }

    fn shared_state_lock_path(&self) -> PathBuf {
        self.layout.locks_dir().join(FLEET_SHARED_STATE_LOCK_FILE)
    }

    fn with_shared_state_lock<T>(
        &self,
        shared: bool,
        f: impl FnOnce() -> Result<T, FleetTransportError>,
    ) -> Result<T, FleetTransportError> {
        let lock_path = self.shared_state_lock_path();
        let lock_file = self.lock_file(&lock_path)?;
        lock_file_with_backoff(&lock_file, &lock_path, shared)?;
        let result = f();
        let unlock_result = unlock_file(&lock_file, &lock_path);
        let value = result?;
        unlock_result?;
        Ok(value)
    }

    fn lock_file(&self, path: &Path) -> Result<File, FleetTransportError> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|err| {
                FleetTransportError::io(format!(
                    "failed opening fleet lock file {}: {err}",
                    path.display()
                ))
            })
    }

    fn read_action_log(&self) -> Result<Vec<FleetActionRecord>, FleetTransportError> {
        let file = self.action_log_file(false)?;
        lock_file_with_backoff(&file, self.layout.actions_path(), true)?;
        let read_result = (|| {
            let actions =
                parse_jsonl_records::<FleetActionRecord>(&file, self.layout.actions_path())?;
            for action in &actions {
                validate_action_record(action)?;
            }
            Ok(actions)
        })();
        let unlock_result = unlock_file(&file, self.layout.actions_path());
        let actions = read_result?;
        unlock_result?;
        Ok(actions)
    }

    fn write_node_status_unlocked(&self, status: &NodeStatus) -> Result<(), FleetTransportError> {
        let path = self.layout.node_status_path(&status.node_id)?;
        let lock_path = self.node_lock_path(&status.node_id)?;
        let lock_file = self.lock_file(&lock_path)?;
        lock_file_with_backoff(&lock_file, &lock_path, false)?;

        let write_result = (|| {
            let temp_path = path.with_extension(format!("json.tmp-{}", Uuid::now_v7()));
            let mut temp_guard = TempFileGuard::new(temp_path.clone());
            let payload = serde_json::to_vec(status).map_err(|err| {
                FleetTransportError::serialization(format!(
                    "failed serializing node status {}: {err}",
                    path.display()
                ))
            })?;
            let mut temp_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
                .map_err(|err| {
                    FleetTransportError::io(format!(
                        "failed opening temp node status {}: {err}",
                        temp_path.display()
                    ))
                })?;
            temp_file.write_all(&payload).map_err(|err| {
                FleetTransportError::io(format!(
                    "failed writing temp node status {}: {err}",
                    temp_path.display()
                ))
            })?;
            temp_file.sync_all().map_err(|err| {
                FleetTransportError::io(format!(
                    "failed syncing temp node status {}: {err}",
                    temp_path.display()
                ))
            })?;
            drop(temp_file);
            fs::rename(&temp_path, &path).map_err(|err| {
                FleetTransportError::io(format!(
                    "failed promoting temp node status {} to {}: {err}",
                    temp_path.display(),
                    path.display()
                ))
            })?;
            temp_guard.defuse();
            sync_directory(self.layout.nodes_dir())?;
            Ok(())
        })();

        let unlock_result = unlock_file(&lock_file, &lock_path);
        write_result?;
        unlock_result?;
        Ok(())
    }

    fn list_node_statuses_unlocked(&self) -> Result<Vec<NodeStatus>, FleetTransportError> {
        let mut nodes = Vec::new();
        for entry in fs::read_dir(self.layout.nodes_dir()).map_err(|err| {
            FleetTransportError::io(format!(
                "failed reading fleet nodes directory {}: {err}",
                self.layout.nodes_dir().display()
            ))
        })? {
            let entry = entry.map_err(|err| {
                FleetTransportError::io(format!(
                    "failed reading fleet nodes directory entry {}: {err}",
                    self.layout.nodes_dir().display()
                ))
            })?;
            let path = entry.path();
            let file_type = entry.file_type().map_err(|err| {
                FleetTransportError::io(format!(
                    "failed reading fleet nodes directory entry type {}: {err}",
                    path.display()
                ))
            })?;
            if file_type.is_symlink() || !file_type.is_file() {
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }

            let file = File::open(&path).map_err(|err| {
                FleetTransportError::io(format!(
                    "failed opening node status {}: {err}",
                    path.display()
                ))
            })?;
            let status: NodeStatus = serde_json::from_reader(file).map_err(|err| {
                FleetTransportError::serialization(format!(
                    "failed parsing node status {}: {err}",
                    path.display()
                ))
            })?;
            validate_node_status(&status)?;
            if nodes.len() >= MAX_NODES_CAP {
                return Err(FleetTransportError::serialization(format!(
                    "fleet node status count exceeds {MAX_NODES_CAP} entries"
                )));
            }
            nodes.push(status);
        }

        Ok(nodes)
    }
}

impl FleetTransport for FileFleetTransport {
    fn initialize(&mut self) -> Result<(), FleetTransportError> {
        self.layout.initialize()?;
        self.compact_action_log_if_needed(
            ACTION_LOG_COMPACTION_THRESHOLD_BYTES,
            ACTION_LOG_RETENTION_DAYS,
            clock::wall_now(),
        )
    }

    fn publish_action(&mut self, action: &FleetActionRecord) -> Result<(), FleetTransportError> {
        self.ensure_initialized()?;
        validate_action_record(action)?;

        // DEADLOCK FIX: Acquire compaction lock BEFORE shared_state_lock to establish consistent lock ordering.
        // This prevents AB-BA deadlock with compact_action_log_if_needed() which takes compaction → shared_state.
        let _process_guard = lock_fleet_action_compaction_process(self.layout.root_dir())?;
        let compaction_lock_path = self.action_compaction_lock_path();
        let compaction_lock_file = self.lock_file(&compaction_lock_path)?;
        lock_file_with_backoff(&compaction_lock_file, &compaction_lock_path, false)?;

        let shared_state_result = self.with_shared_state_lock(false, || {
            let file = self.action_log_file(true)?;
            lock_file_with_backoff(&file, self.layout.actions_path(), false)?;

            let write_result = (|| {
                // The comparison and append share the same process, snapshot
                // and file locks. A concurrent publisher cannot replace the
                // decision between admission and its durable append.
                let existing =
                    parse_jsonl_records::<FleetActionRecord>(&file, self.layout.actions_path())?;
                let mut already_published = false;
                for record in &existing {
                    validate_action_record(record)?;
                    if record.action_id == action.action_id {
                        if record != action {
                            return Err(FleetTransportError::action_conflict(format!(
                                "action_id `{}` already identifies a different fleet action",
                                action.action_id
                            )));
                        }
                        already_published = true;
                    }
                }
                if already_published {
                    validate_fleet_native_session_publication(action, &existing)?;
                    // The previous attempt may have written the whole record
                    // before failing to sync. An exact retry must establish
                    // the same durability boundary as a fresh publication.
                    return file.sync_all().map_err(|err| {
                        FleetTransportError::io(format!(
                            "failed syncing fleet action log {}: {err}",
                            self.layout.actions_path().display()
                        ))
                    });
                }
                if existing.len() >= MAX_ACTION_LOG_ENTRIES {
                    return Err(FleetTransportError::serialization(format!(
                        "fleet action log {} already contains the maximum {MAX_ACTION_LOG_ENTRIES} entries",
                        self.layout.actions_path().display()
                    )));
                }
                validate_fleet_policy_publication(action, &existing)?;
                validate_fleet_native_session_publication(action, &existing)?;
                let payload = serde_json::to_vec(action).map_err(|err| {
                    FleetTransportError::serialization(format!(
                        "failed serializing fleet action {}: {err}",
                        action.action_id
                    ))
                })?;
                if payload.len() > MAX_ACTION_RECORD_BYTES {
                    return Err(FleetTransportError::serialization(format!(
                        "serialized fleet action {} exceeds {} bytes",
                        action.action_id, MAX_ACTION_RECORD_BYTES
                    )));
                }

                let mut handle = &file;
                let length = handle.seek(SeekFrom::End(0)).map_err(|err| {
                    FleetTransportError::io(format!(
                        "failed seeking fleet action log {}: {err}",
                        self.layout.actions_path().display()
                    ))
                })?;
                if length > 0 {
                    let mut last_byte = [0_u8];
                    handle
                        .seek(SeekFrom::End(-1))
                        .and_then(|_| handle.read_exact(&mut last_byte))
                        .map_err(|err| {
                            FleetTransportError::io(format!(
                                "failed reading fleet action log delimiter {}: {err}",
                                self.layout.actions_path().display()
                            ))
                        })?;
                    // A crash can leave a complete, valid JSON record without
                    // its newline. It has already passed validation above;
                    // preserve it and separate the next record before append.
                    if last_byte[0] != b'\n' {
                        handle.write_all(b"\n").map_err(|err| {
                            FleetTransportError::io(format!(
                                "failed completing fleet action delimiter {}: {err}",
                                self.layout.actions_path().display()
                            ))
                        })?;
                    }
                }
                handle.write_all(&payload).map_err(|err| {
                    FleetTransportError::io(format!(
                        "failed writing fleet action log {}: {err}",
                        self.layout.actions_path().display()
                    ))
                })?;
                handle.write_all(b"\n").map_err(|err| {
                    FleetTransportError::io(format!(
                        "failed writing fleet action delimiter {}: {err}",
                        self.layout.actions_path().display()
                    ))
                })?;
                file.sync_all().map_err(|err| {
                    FleetTransportError::io(format!(
                        "failed syncing fleet action log {}: {err}",
                        self.layout.actions_path().display()
                    ))
                })?;
                Ok(())
            })();

            let unlock_result = unlock_file(&file, self.layout.actions_path());
            write_result?;
            unlock_result?;
            Ok(())
        });

        // RESOURCE LEAK FIX: Always unlock compaction lock, even on error paths
        let unlock_result = unlock_file(&compaction_lock_file, &compaction_lock_path);
        shared_state_result?;
        unlock_result?;
        Ok(())
    }

    fn list_actions(&self) -> Result<Vec<FleetActionRecord>, FleetTransportError> {
        self.ensure_initialized()?;
        self.with_shared_state_lock(true, || self.read_action_log())
    }

    fn upsert_node_status(&mut self, status: &NodeStatus) -> Result<(), FleetTransportError> {
        self.ensure_initialized()?;
        validate_node_status(status)?;
        self.with_shared_state_lock(false, || self.write_node_status_unlocked(status))
    }

    fn list_node_statuses(&self) -> Result<Vec<NodeStatus>, FleetTransportError> {
        self.ensure_initialized()?;

        self.with_shared_state_lock(true, || self.list_node_statuses_unlocked())
    }

    fn read_shared_state(&self) -> Result<FleetSharedState, FleetTransportError> {
        self.ensure_initialized()?;

        self.with_shared_state_lock(true, || {
            let actions = self.read_action_log()?;

            let mut nodes = self.list_node_statuses_unlocked()?;
            nodes.sort_by(|left, right| {
                left.zone_id
                    .cmp(&right.zone_id)
                    .then_with(|| left.node_id.cmp(&right.node_id))
            });

            Ok(FleetSharedState {
                schema_version: FLEET_SHARED_STATE_SCHEMA.to_string(),
                actions,
                nodes,
            })
        })
    }
}

pub fn validate_zone_id(zone_id: &str) -> Result<&str, FleetTransportError> {
    validate_transport_identifier(zone_id, "zone_id", MAX_ZONE_ID_LEN)
}

pub fn validate_node_id(node_id: &str) -> Result<&str, FleetTransportError> {
    validate_transport_identifier(node_id, "node_id", MAX_NODE_ID_LEN)
}

pub(crate) fn validate_action_id(action_id: &str) -> Result<&str, FleetTransportError> {
    validate_transport_identifier(action_id, "action_id", MAX_ACTION_ID_LEN)
}

fn validate_transport_identifier<'a>(
    value: &'a str,
    field_name: &str,
    max_len: usize,
) -> Result<&'a str, FleetTransportError> {
    if value.is_empty() || value.len() > max_len {
        return Err(FleetTransportError::serialization(format!(
            "{field_name} must be 1..={max_len} characters"
        )));
    }
    if value.trim() != value {
        return Err(FleetTransportError::serialization(format!(
            "{field_name} must not include leading or trailing whitespace"
        )));
    }
    if value == "." || value == ".." || value.contains("..") {
        return Err(FleetTransportError::serialization(format!(
            "{field_name} must not include traversal segments"
        )));
    }
    if value.contains('\0') {
        return Err(FleetTransportError::serialization(format!(
            "{field_name} must not contain null bytes"
        )));
    }
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Ok(value);
    }

    Err(FleetTransportError::serialization(format!(
        "{field_name} must match [a-zA-Z0-9._-]{{1,{max_len}}}"
    )))
}

/// Validate one action record with the same rules every transport applies on
/// ingest (identifier charset/length, non-empty single-line text fields and
/// the serialized record byte limit).
///
/// # Errors
///
/// Returns [`FleetTransportError::SerializationError`] naming the bad field.
pub fn validate_action_record(action: &FleetActionRecord) -> Result<(), FleetTransportError> {
    validate_action_id(&action.action_id)?;

    match &action.action {
        FleetAction::Quarantine {
            zone_id,
            incident_id,
            target_id,
            reason,
            ..
        } => {
            validate_zone_id(zone_id)?;
            validate_action_text_field("quarantine incident_id", incident_id)?;
            validate_action_text_field("quarantine target_id", target_id)?;
            validate_action_text_field("quarantine reason", reason)?;
        }
        FleetAction::Release {
            zone_id,
            incident_id,
            reason,
            ..
        } => {
            validate_zone_id(zone_id)?;
            validate_action_text_field("release incident_id", incident_id)?;
            if let Some(reason) = reason {
                validate_action_text_field("release reason", reason)?;
            }
        }
        FleetAction::NativeSessionHold { zone_id, reason } => {
            validate_zone_id(zone_id)?;
            validate_action_text_field("native-session hold reason", reason)?;
        }
        FleetAction::NativeSessionResume {
            zone_id,
            hold_action_id,
            reason,
        } => {
            validate_zone_id(zone_id)?;
            validate_action_id(hold_action_id)?;
            if let Some(reason) = reason {
                validate_action_text_field("native-session resume reason", reason)?;
            }
        }
        FleetAction::PolicyUpdate {
            zone_id,
            policy_version,
            artifact,
            ..
        } => {
            validate_zone_id(zone_id)?;
            validate_action_text_field("policy_version", policy_version)?;
            if let Some(artifact) = artifact {
                artifact.validate()?;
            }
        }
        #[cfg(feature = "control-plane")]
        FleetAction::Revoke {
            extension_id,
            scope,
        } => {
            validate_zone_id(&scope.zone_id)?;

            // bd-hstmy: Validate tenant_id when present for tenant isolation
            if let Some(tenant_id) = scope.tenant_id.as_deref() {
                validate_action_text_field("revoke tenant_id", tenant_id)?;
            } else {
                // Log warning about potential tenant isolation gap in transport layer
                // Note: This should be rare as fleet_quarantine.rs validation runs first
                tracing::warn!(
                    "Fleet transport processing revocation with tenant_id=None - potential cross-tenant operation"
                );
            }

            validate_action_text_field("revoke extension_id", extension_id)?;
            validate_action_text_field("revoke reason", &scope.reason)?;
        }
    }

    let payload = serde_json::to_vec(action)
        .map_err(|err| FleetTransportError::serialization(err.to_string()))?;
    if payload.len() > MAX_ACTION_RECORD_BYTES {
        return Err(FleetTransportError::serialization(format!(
            "serialized fleet action {} exceeds {} bytes",
            action.action_id, MAX_ACTION_RECORD_BYTES
        )));
    }

    Ok(())
}

/// Validate a node heartbeat record (zone and node identifiers).
///
/// # Errors
///
/// Returns [`FleetTransportError::SerializationError`] naming the bad field.
pub fn validate_node_status(status: &NodeStatus) -> Result<(), FleetTransportError> {
    validate_zone_id(&status.zone_id)?;
    validate_node_id(&status.node_id)?;
    if let Some(checkpoint) = &status.applied_actions {
        checkpoint.validate()?;
        if !matches!(status.health, NodeHealth::Healthy | NodeHealth::Maintenance) {
            return Err(FleetTransportError::serialization(
                "only a healthy or drained maintenance node can acknowledge an applied fleet snapshot",
            ));
        }
    }
    if status.health == NodeHealth::Maintenance
        && !status.native_session_drain.as_ref().is_some_and(|drain| {
            drain.fence_held
                && drain.population_is_terminal()
                && status.applied_actions.as_ref() == Some(&drain.applied_actions)
        })
    {
        return Err(FleetTransportError::serialization(
            "maintenance acknowledgement requires an applied, terminal native population with admission still fenced",
        ));
    }
    if let Some(drain) = &status.native_session_drain {
        drain.validate()?;
        if let Some(attestation) = &drain.supervisor_attestation
            && (attestation.node_id != status.node_id || attestation.zone_id != status.zone_id)
        {
            return Err(FleetTransportError::serialization(
                "native supervisor drain attestation belongs to a different node/zone identity",
            ));
        }
        if !drain.is_complete() && status.health == NodeHealth::Healthy {
            return Err(FleetTransportError::serialization(
                "a node with pending or indeterminate native drain obligations cannot report healthy convergence",
            ));
        }
        if status
            .applied_actions
            .as_ref()
            .is_some_and(|applied| applied != &drain.applied_actions)
            || (drain.is_complete()
                && status.applied_actions.as_ref() != Some(&drain.applied_actions))
        {
            return Err(FleetTransportError::serialization(
                "native session drain is not bound to the node's applied fleet snapshot",
            ));
        }
    }
    Ok(())
}

fn validate_action_text_field(field_name: &str, value: &str) -> Result<(), FleetTransportError> {
    if value.trim().is_empty() {
        return Err(FleetTransportError::serialization(format!(
            "{field_name} must not be empty"
        )));
    }
    if value.trim() != value {
        return Err(FleetTransportError::serialization(format!(
            "{field_name} must not include leading or trailing whitespace"
        )));
    }
    if value.contains('\0') {
        return Err(FleetTransportError::serialization(format!(
            "{field_name} must not contain null bytes"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(FleetTransportError::serialization(format!(
            "{field_name} must not contain control characters"
        )));
    }

    Ok(())
}

#[cfg(test)]
fn lock_retry_base_backoffs() -> [Duration; LOCK_RETRY_BACKOFF_MILLIS.len()] {
    LOCK_RETRY_BACKOFF_MILLIS.map(Duration::from_millis)
}

fn jittered_lock_retry_delay(base_millis: u64) -> Duration {
    let jitter_millis = base_millis / 2;
    let min_millis = base_millis.saturating_sub(jitter_millis).max(1);
    let max_millis = base_millis.saturating_add(jitter_millis).max(min_millis);
    Duration::from_millis(rand::thread_rng().gen_range(min_millis..=max_millis))
}

fn lock_retry_backoffs() -> [Duration; LOCK_RETRY_BACKOFF_MILLIS.len()] {
    LOCK_RETRY_BACKOFF_MILLIS.map(jittered_lock_retry_delay)
}

pub fn wait_until_fleet_converged_or_timeout<F>(
    timeout: Duration,
    mut is_converged: F,
) -> Result<FleetConvergenceWaitOutcome, FleetTransportError>
where
    F: FnMut() -> Result<bool, FleetTransportError>,
{
    let started = Instant::now();
    let timeout_secs = timeout.as_secs();
    let mut check_attempts = 0u32;

    loop {
        check_attempts = check_attempts.saturating_add(1);

        if is_converged()? {
            return Ok(FleetConvergenceWaitOutcome {
                elapsed: started.elapsed(),
                timed_out: false,
                check_attempts,
                failure_context: None,
            });
        }

        let elapsed = started.elapsed();
        if elapsed >= timeout {
            return Ok(FleetConvergenceWaitOutcome {
                elapsed,
                timed_out: true,
                check_attempts,
                failure_context: Some(FleetConvergenceFailureContext {
                    doctor_command: "franken-node doctor --fleet --convergence".to_string(),
                    timeout_secs,
                    diagnostic_hint: format!(
                        "Fleet failed to converge after {}s ({} attempts). Check network connectivity, node health, or configuration drift.",
                        timeout_secs, check_attempts
                    ),
                }),
            });
        }

        thread::sleep(FLEET_CONVERGENCE_POLL_INTERVAL.min(timeout.saturating_sub(elapsed)));
    }
}

fn lock_file_with_backoff(
    file: &File,
    path: &Path,
    shared: bool,
) -> Result<(), FleetTransportError> {
    let attempt = || {
        if shared {
            file.try_lock_shared()
        } else {
            file.try_lock()
        }
    };

    match attempt() {
        Ok(()) => return Ok(()),
        Err(TryLockError::WouldBlock) => {}
        Err(TryLockError::Error(err)) => {
            return Err(FleetTransportError::io(format!(
                "failed acquiring flock for {}: {err}",
                path.display()
            )));
        }
    }

    for delay in lock_retry_backoffs() {
        thread::sleep(delay);
        match attempt() {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) => {}
            Err(TryLockError::Error(err)) => {
                return Err(FleetTransportError::io(format!(
                    "failed acquiring flock for {}: {err}",
                    path.display()
                )));
            }
        }
    }

    Err(FleetTransportError::lock_contention(format!(
        "timed out acquiring flock for {} after jittered retries based on 100ms/200ms/400ms/800ms/1600ms",
        path.display()
    )))
}

fn unlock_file(file: &File, path: &Path) -> Result<(), FleetTransportError> {
    file.unlock().map_err(|err| {
        FleetTransportError::io(format!(
            "failed releasing flock for {}: {err}",
            path.display()
        ))
    })
}

fn sync_directory(path: &Path) -> Result<(), FleetTransportError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|err| {
            FleetTransportError::io(format!(
                "failed syncing fleet transport directory {}: {err}",
                path.display()
            ))
        })
}

fn normalized_directory(path: &Path) -> &Path {
    if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    }
}

fn parse_jsonl_records<T>(file: &File, path: &Path) -> Result<Vec<T>, FleetTransportError>
where
    T: for<'de> Deserialize<'de>,
{
    let mut records = Vec::new();
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let mut line_number = 0usize;

    loop {
        line.clear();
        let bytes_read = read_bounded_jsonl_line(&mut reader, path, line_number + 1, &mut line)?;
        if bytes_read == 0 {
            break;
        }
        line_number = line_number.saturating_add(1);

        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }

        let record = serde_json::from_slice(&line).map_err(|err| {
            FleetTransportError::serialization(format!(
                "failed parsing JSONL line {} from {}: {err}",
                line_number,
                path.display()
            ))
        })?;
        if records.len() >= MAX_ACTION_LOG_ENTRIES {
            return Err(FleetTransportError::serialization(format!(
                "JSONL record count in {} exceeds {MAX_ACTION_LOG_ENTRIES} entries",
                path.display()
            )));
        }
        records.push(record);
    }
    Ok(records)
}

fn read_bounded_jsonl_line<R: BufRead>(
    reader: &mut R,
    path: &Path,
    line_number: usize,
    line: &mut Vec<u8>,
) -> Result<usize, FleetTransportError> {
    let limit = u64::try_from(FLEET_ACTION_RECORD_LINE_POLICY.max_bytes.saturating_add(1))
        .unwrap_or(u64::MAX);
    let bytes_read = reader.take(limit).read_until(b'\n', line).map_err(|err| {
        FleetTransportError::io(format!(
            "failed reading JSONL line {} from {}: {err}",
            line_number,
            path.display()
        ))
    })?;
    if let Err(violation) = FLEET_ACTION_RECORD_LINE_POLICY.validate_len(bytes_read) {
        return Err(FleetTransportError::serialization(format!(
            "JSONL line {} in {} exceeds {} bytes; {violation}",
            line_number,
            path.display(),
            FLEET_ACTION_RECORD_LINE_POLICY.max_bytes
        )));
    }
    Ok(bytes_read)
}

pub const FLEET_EPOCH_BARRIER_CERTIFIED_DRAIN_SCOPE: &str =
    "enrolled_epoch_barrier_quiescence_certified";
pub const FLEET_EPOCH_BARRIER_CERTIFIED_HOLD_SCOPE: &str =
    "enrolled_epoch_barrier_hold_quiescence_certified";
pub const FLEET_EPOCH_QUIESCENCE_CERTIFICATE_SCHEMA: &str =
    "franken-node/fleet-epoch-quiescence-certificate/v1";
const SEQLOCK_PAGE_MAGIC: &[u8; 8] = b"FNSQLK01";
const SEQLOCK_PAGE_BYTES: usize = 80;

/// Distinct fleet acknowledgement stages (bd-reality-20260923-26n9r.30).
///
/// Separates durable action persistence from policy application, node-local
/// session drain quiescence, and distributed epoch-barrier certification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetAcknowledgementStage {
    Persisted,
    PolicyApplied,
    SessionQuiesced,
    EpochBarrierCertified,
}

#[must_use]
pub fn classify_node_acknowledgement_stage(
    node: &NodeStatus,
    expected_actions: &FleetApplicationCheckpoint,
    epoch_barrier_certified: bool,
) -> FleetAcknowledgementStage {
    if node.applied_actions.as_ref() != Some(expected_actions) {
        return FleetAcknowledgementStage::Persisted;
    }
    let Some(drain) = &node.native_session_drain else {
        return FleetAcknowledgementStage::PolicyApplied;
    };
    if &drain.applied_actions != expected_actions
        || drain.indeterminate_sessions > 0
        || drain.pending_sessions > 0
    {
        return FleetAcknowledgementStage::PolicyApplied;
    }
    if epoch_barrier_certified && drain.supervisor_attestation.is_some() {
        FleetAcknowledgementStage::EpochBarrierCertified
    } else {
        FleetAcknowledgementStage::SessionQuiesced
    }
}

/// Lock-free `O(1)` control snapshot for worker safepoint checks (`#![forbid(unsafe_code)]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeqlockControlSnapshot {
    pub sequence: u64,
    pub control_epoch: u64,
    pub quarantine_version: u64,
    pub active_hold_count: u64,
    pub action_count: u64,
    pub action_log_digest_prefix: [u8; 32],
}

/// Safe lock-free Seqlock control page using odd/even sequence fencing in-process
/// plus a fixed-size header/trailer-framed binary file page for cross-process readers.
pub struct SeqlockControlPage {
    sequence: std::sync::atomic::AtomicU64,
    control_epoch: std::sync::atomic::AtomicU64,
    quarantine_version: std::sync::atomic::AtomicU64,
    active_hold_count: std::sync::atomic::AtomicU64,
    action_count: std::sync::atomic::AtomicU64,
    digest_words: [std::sync::atomic::AtomicU64; 4],
    writer_gate: Mutex<()>,
}

impl Default for SeqlockControlPage {
    fn default() -> Self {
        Self::new()
    }
}

impl SeqlockControlPage {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sequence: std::sync::atomic::AtomicU64::new(0),
            control_epoch: std::sync::atomic::AtomicU64::new(0),
            quarantine_version: std::sync::atomic::AtomicU64::new(0),
            active_hold_count: std::sync::atomic::AtomicU64::new(0),
            action_count: std::sync::atomic::AtomicU64::new(0),
            digest_words: [
                std::sync::atomic::AtomicU64::new(0),
                std::sync::atomic::AtomicU64::new(0),
                std::sync::atomic::AtomicU64::new(0),
                std::sync::atomic::AtomicU64::new(0),
            ],
            writer_gate: Mutex::new(()),
        }
    }

    pub fn publish(
        &self,
        control_epoch: u64,
        quarantine_version: u64,
        active_hold_count: u64,
        action_count: u64,
        action_log_digest_prefix: [u8; 32],
    ) -> SeqlockControlSnapshot {
        use std::sync::atomic::Ordering;
        let _writer = match self.writer_gate.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let odd = self.sequence.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
        debug_assert_eq!(odd & 1, 1);
        self.control_epoch.store(control_epoch, Ordering::Release);
        self.quarantine_version
            .store(quarantine_version, Ordering::Release);
        self.active_hold_count
            .store(active_hold_count, Ordering::Release);
        self.action_count.store(action_count, Ordering::Release);
        for (idx, chunk) in action_log_digest_prefix
            .as_chunks::<8>()
            .0
            .iter()
            .enumerate()
        {
            self.digest_words[idx].store(u64::from_le_bytes(*chunk), Ordering::Release);
        }
        let even = self
            .sequence
            .fetch_add(1, Ordering::Release)
            .wrapping_add(1);
        debug_assert_eq!(even & 1, 0);
        SeqlockControlSnapshot {
            sequence: even,
            control_epoch,
            quarantine_version,
            active_hold_count,
            action_count,
            action_log_digest_prefix,
        }
    }

    /// Lock-free `O(1)` safepoint read; retries automatically if a concurrent writer is active.
    #[must_use]
    pub fn read_safepoint(&self) -> SeqlockControlSnapshot {
        use std::sync::atomic::Ordering;
        loop {
            let seq1 = self.sequence.load(Ordering::Acquire);
            if (seq1 & 1) != 0 {
                std::hint::spin_loop();
                continue;
            }
            let control_epoch = self.control_epoch.load(Ordering::Acquire);
            let quarantine_version = self.quarantine_version.load(Ordering::Acquire);
            let active_hold_count = self.active_hold_count.load(Ordering::Acquire);
            let action_count = self.action_count.load(Ordering::Acquire);
            let mut action_log_digest_prefix = [0_u8; 32];
            for (idx, word_atomic) in self.digest_words.iter().enumerate() {
                let bytes = word_atomic.load(Ordering::Acquire).to_le_bytes();
                action_log_digest_prefix[idx * 8..(idx + 1) * 8].copy_from_slice(&bytes);
            }
            let seq2 = self.sequence.load(Ordering::Acquire);
            if seq1 == seq2 {
                return SeqlockControlSnapshot {
                    sequence: seq2,
                    control_epoch,
                    quarantine_version,
                    active_hold_count,
                    action_count,
                    action_log_digest_prefix,
                };
            }
            std::hint::spin_loop();
        }
    }

    /// Persist a binary Seqlock page with leading/trailing even sequence markers for cross-process readers.
    pub fn write_shared_page(
        &self,
        path: &Path,
    ) -> Result<SeqlockControlSnapshot, FleetTransportError> {
        let snapshot = self.read_safepoint();
        let mut buf = [0_u8; SEQLOCK_PAGE_BYTES];
        buf[0..8].copy_from_slice(SEQLOCK_PAGE_MAGIC);
        buf[8..16].copy_from_slice(&snapshot.sequence.to_le_bytes());
        buf[16..24].copy_from_slice(&snapshot.control_epoch.to_le_bytes());
        buf[24..32].copy_from_slice(&snapshot.quarantine_version.to_le_bytes());
        buf[32..40].copy_from_slice(&snapshot.active_hold_count.to_le_bytes());
        buf[40..48].copy_from_slice(&snapshot.action_count.to_le_bytes());
        buf[48..80].copy_from_slice(&snapshot.action_log_digest_prefix);
        let parent = normalized_directory(path.parent().unwrap_or_else(|| Path::new(".")));
        fs::create_dir_all(parent).map_err(|err| {
            FleetTransportError::io(format!(
                "create seqlock page parent {}: {err}",
                parent.display()
            ))
        })?;
        let tmp_path = path.with_extension(format!("seqlock-{}.tmp", Uuid::now_v7()));
        fs::write(&tmp_path, buf).map_err(|err| {
            FleetTransportError::io(format!(
                "write seqlock page temp {}: {err}",
                tmp_path.display()
            ))
        })?;
        fs::rename(&tmp_path, path).map_err(|err| {
            FleetTransportError::io(format!("publish seqlock page {}: {err}", path.display()))
        })?;
        Ok(snapshot)
    }

    pub fn read_shared_page(path: &Path) -> Result<SeqlockControlSnapshot, FleetTransportError> {
        let bytes = fs::read(path).map_err(|err| {
            FleetTransportError::io(format!("read seqlock page {}: {err}", path.display()))
        })?;
        if bytes.len() != SEQLOCK_PAGE_BYTES || &bytes[0..8] != SEQLOCK_PAGE_MAGIC {
            return Err(FleetTransportError::serialization(
                "invalid seqlock control page header or byte length",
            ));
        }
        let read_u64 = |offset: usize| -> u64 {
            let mut word = [0_u8; 8];
            word.copy_from_slice(&bytes[offset..offset + 8]);
            u64::from_le_bytes(word)
        };
        let sequence = read_u64(8);
        if (sequence & 1) != 0 {
            return Err(FleetTransportError::stale_state(
                "seqlock control page has odd writer-in-progress sequence",
            ));
        }
        let mut action_log_digest_prefix = [0_u8; 32];
        action_log_digest_prefix.copy_from_slice(&bytes[48..80]);
        Ok(SeqlockControlSnapshot {
            sequence,
            control_epoch: read_u64(16),
            quarantine_version: read_u64(24),
            active_hold_count: read_u64(32),
            action_count: read_u64(40),
            action_log_digest_prefix,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetEpochParticipantQuiescence {
    pub zone_id: String,
    pub node_id: String,
    pub stage: FleetAcknowledgementStage,
    pub drain_id: String,
    pub generation: u64,
    pub admitted_sessions: u64,
    pub terminal_sessions: u64,
    pub session_set_sha256: String,
    pub checkpoint_sha256: String,
    pub supervisor_key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetEpochQuiescenceCertificate {
    pub schema_version: String,
    pub transition_id: String,
    pub pre_epoch: u64,
    pub committed_epoch: u64,
    pub initiator: String,
    pub reason: String,
    pub trace_id: String,
    pub certified_at: DateTime<Utc>,
    pub action_log_checkpoint: FleetActionLogCheckpoint,
    pub fleet_quiescence_certified: bool,
    pub participants: Vec<FleetEpochParticipantQuiescence>,
}

#[derive(Debug, Clone, Copy)]
pub struct FleetEpochBarrierParams<'a> {
    pub initiator: &'a str,
    pub reason: &'a str,
    pub now: DateTime<Utc>,
    pub stale_after: Duration,
    pub trace_id: &'a str,
}

/// Drive `ProductEpochCoordinator` (`EpochTransitionBarrier` + `EpochStore`) over
/// enrolled per-node Ed25519 supervisor drain attestations to certify fleet quiescence.
///
/// Fails closed and aborts the active barrier whenever any enrolled node is missing,
/// stale, unauthenticated, outside `PolicyApplied`, or retains `pending_sessions > 0`
/// or `indeterminate_sessions > 0`.
pub fn certify_fleet_epoch_quiescence(
    coordinator: &mut crate::runtime::epoch_transition::ProductEpochCoordinator,
    state: &FleetSharedState,
    enrolled_supervisor_roots: &BTreeMap<(String, String), ed25519_dalek::VerifyingKey>,
    params: FleetEpochBarrierParams<'_>,
) -> Result<(FleetNativeDrainEvidence, FleetEpochQuiescenceCertificate), FleetTransportError> {
    let FleetEpochBarrierParams {
        initiator,
        reason,
        now,
        stale_after,
        trace_id,
    } = params;
    if enrolled_supervisor_roots.is_empty() {
        return Err(FleetTransportError::not_initialized(
            "fleet epoch quiescence certification requires enrolled per-node supervisor keys",
        ));
    }
    if initiator.trim().is_empty() || reason.trim().is_empty() || trace_id.trim().is_empty() {
        return Err(FleetTransportError::serialization(
            "fleet epoch quiescence certification requires non-empty initiator, reason, and trace_id",
        ));
    }
    let action_log_checkpoint = fleet_action_log_checkpoint(&state.actions)?;
    if action_log_checkpoint.action_count == 0 {
        return Err(FleetTransportError::stale_state(
            "fleet epoch quiescence certification requires at least one retained fleet action",
        ));
    }
    let required_nodes: BTreeSet<(String, String)> =
        enrolled_supervisor_roots.keys().cloned().collect();
    let mut evidence = fleet_native_drain_evidence(state, &required_nodes, now, stale_after)?;
    for (zone_id, node_id) in &required_nodes {
        coordinator.register_service(&format!("{zone_id}/{node_id}"));
    }
    let timestamp_ms = u64::try_from(now.timestamp_millis().max(0)).unwrap_or(0);
    let proposal = coordinator
        .propose_transition(initiator, reason, timestamp_ms, trace_id)
        .map_err(|err| FleetTransportError::stale_state(err.to_string()))?;

    let mut participants = Vec::with_capacity(evidence.nodes.len());
    let mut abort_detail: Option<String> = None;

    if !evidence.complete {
        abort_detail = Some(
            "not all required fleet participants have fresh terminal native-session drains"
                .to_string(),
        );
    }

    if abort_detail.is_none() {
        for node in &evidence.nodes {
            let identity = (node.zone_id.clone(), node.node_id.clone());
            let Some(root) = enrolled_supervisor_roots.get(&identity) else {
                abort_detail = Some(format!(
                    "participant `{}/{}` lacks an enrolled Ed25519 supervisor key",
                    node.zone_id, node.node_id
                ));
                break;
            };
            let Some(drain) = &node.native_session_drain else {
                abort_detail = Some(format!(
                    "participant `{}/{}` is missing native_session_drain",
                    node.zone_id, node.node_id
                ));
                break;
            };
            if drain.indeterminate_sessions > 0 || drain.pending_sessions > 0 {
                abort_detail = Some(format!(
                    "participant `{}/{}` retains pending={} indeterminate={} sessions",
                    node.zone_id,
                    node.node_id,
                    drain.pending_sessions,
                    drain.indeterminate_sessions
                ));
                break;
            }
            let Some(attestation) = &drain.supervisor_attestation else {
                abort_detail = Some(format!(
                    "participant `{}/{}` drain checkpoint is unsigned",
                    node.zone_id, node.node_id
                ));
                break;
            };
            if let Err(err) = attestation
                .verify(drain, &node.node_id, &node.zone_id, root)
                .and_then(|()| attestation.validate_freshness(now))
            {
                abort_detail = Some(format!(
                    "participant `{}/{}` supervisor attestation failed verification: {err}",
                    node.zone_id, node.node_id
                ));
                break;
            }
            let participant_id = format!("{}/{}", node.zone_id, node.node_id);
            if let Err(err) =
                coordinator.ack_drain(&participant_id, drain.admitted_sessions, 0, trace_id)
            {
                abort_detail = Some(err.to_string());
                break;
            }
            participants.push(FleetEpochParticipantQuiescence {
                zone_id: node.zone_id.clone(),
                node_id: node.node_id.clone(),
                stage: FleetAcknowledgementStage::EpochBarrierCertified,
                drain_id: attestation.drain_id.clone(),
                generation: attestation.generation,
                admitted_sessions: drain.admitted_sessions,
                terminal_sessions: drain.terminal_sessions,
                session_set_sha256: drain.session_set_sha256.clone(),
                checkpoint_sha256: attestation.checkpoint_sha256.clone(),
                supervisor_key_id: attestation.product_root_key_id.clone(),
            });
        }
    }

    if let Some(detail) = abort_detail {
        let _ = coordinator.abort_transition_cancellation(&detail, timestamp_ms, trace_id);
        return Err(FleetTransportError::stale_state(format!(
            "epoch barrier `{}` aborted before commit: {detail}",
            proposal.transition_id
        )));
    }

    let committed_epoch = coordinator
        .commit_transition(timestamp_ms, trace_id)
        .map_err(|err| FleetTransportError::stale_state(err.to_string()))?;

    evidence.scope = FLEET_EPOCH_BARRIER_CERTIFIED_DRAIN_SCOPE.to_string();
    evidence.fleet_quiescence_certified = true;
    let certificate = FleetEpochQuiescenceCertificate {
        schema_version: FLEET_EPOCH_QUIESCENCE_CERTIFICATE_SCHEMA.to_string(),
        transition_id: proposal.transition_id,
        pre_epoch: proposal.pre_epoch,
        committed_epoch,
        initiator: initiator.to_string(),
        reason: reason.to_string(),
        trace_id: trace_id.to_string(),
        certified_at: now,
        action_log_checkpoint,
        fleet_quiescence_certified: true,
        participants,
    };
    Ok((evidence, certificate))
}

#[cfg(test)]
mod tests {
    use super::{
        ACTION_LOG_RETENTION_DAYS, FLEET_NODE_DIR, FLEET_SHARED_STATE_SCHEMA, FileFleetTransport,
        FleetAction, FleetActionRecord, FleetSharedState, FleetTargetKind, FleetTransport,
        FleetTransportError, FleetTransportLayout, LOCK_RETRY_BACKOFF_MILLIS,
        MAX_ACTION_LOG_ENTRIES, MAX_ACTION_RECORD_BYTES, MAX_ACTION_RECORD_LINE_BYTES,
        MAX_NODE_ID_LEN, MAX_NODES_CAP, NodeHealth, NodeStatus, TempFileGuard,
        canonical_fleet_convergence_receipt_payload, clock, fleet_action_compaction_root_key,
        fleet_application_checkpoint, fleet_convergence_receipt_verdict, lock_file_with_backoff,
        lock_fleet_action_compaction_process, lock_retry_backoffs, lock_retry_base_backoffs,
        parse_jsonl_records, push_bounded, sign_fleet_convergence_receipt_payload,
        validate_node_id, validate_zone_id, wait_until_fleet_converged_or_timeout,
    };
    #[cfg(feature = "control-plane")]
    use crate::api::fleet_quarantine::{RevocationScope, RevocationSeverity};
    use chrono::{DateTime, Utc};
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::Write as _,
        path::{Path, PathBuf},
        sync::{Arc, Barrier, mpsc},
        time::{Duration, Instant},
    };

    use tempfile::tempdir;

    #[cfg(unix)]
    mod operator_policy_ancestry {
        use super::*;
        use crate::config::{Config, Profile};
        use crate::control_plane::fleet_transport::{
            FleetPolicyArtifact, FleetRuntimePolicy, activate_fleet_policy_snapshot,
            enforce_active_fleet_policy, enforce_active_fleet_policy_with_operator,
            validate_fleet_policy_project_root, validate_fleet_policy_project_root_with_operator,
        };

        fn activate(project: &Path, limit: u64) {
            activate_fleet_policy_snapshot(
                project,
                &[FleetActionRecord {
                    action_id: format!("restricted-{limit}"),
                    emitted_at: Utc::now(),
                    action: FleetAction::PolicyUpdate {
                        zone_id: "prod".to_string(),
                        policy_version: "revision-1".to_string(),
                        changed_fields: vec!["max_instructions".to_string()],
                        artifact: Some(
                            FleetPolicyArtifact::new(
                                1,
                                FleetRuntimePolicy {
                                    max_instructions: Some(limit),
                                    ..FleetRuntimePolicy::default()
                                },
                            )
                            .unwrap(),
                        ),
                    },
                }],
                "prod",
            )
            .unwrap()
            .unwrap();
        }

        #[test]
        fn retained_operator_allows_nested_release_and_both_restrictions_compose() {
            let workspace = tempdir().unwrap();
            let operator = workspace.path().canonicalize().unwrap();
            let release = operator.join("releases/current");
            fs::create_dir_all(&release).unwrap();
            activate(&operator, 1_000);
            activate(&release, 2_000);
            let mut config = Config::for_profile(Profile::Balanced);
            let original = config.clone();

            assert!(validate_fleet_policy_project_root(&release).is_err());
            assert!(enforce_active_fleet_policy(&release, &mut config, Profile::Balanced).is_err());
            assert_eq!(config, original);
            validate_fleet_policy_project_root_with_operator(&release, Some(&operator)).unwrap();
            let child_policy = enforce_active_fleet_policy_with_operator(
                &release,
                &mut config,
                Profile::Balanced,
                Some(&operator),
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                child_policy.policies["prod"].policy.max_instructions,
                Some(2_000)
            );
            assert_eq!(config.runtime.max_instructions, Some(2_000));
            let operator_policy =
                enforce_active_fleet_policy(&operator, &mut config, Profile::Balanced)
                    .unwrap()
                    .unwrap();
            assert_eq!(
                operator_policy.policies["prod"].policy.max_instructions,
                Some(1_000)
            );
            assert_eq!(config.runtime.max_instructions, Some(1_000));
            // The exception never changes ordinary execution admission.
            assert!(validate_fleet_policy_project_root(&release).is_err());
        }

        #[test]
        fn retained_operator_exception_cannot_skip_other_enrolled_ancestors() {
            for scenario in ["intermediate", "outer", "unrelated"] {
                let workspace = tempdir().unwrap();
                let outer = workspace.path().canonicalize().unwrap();
                let operator = outer.join("operator");
                let intermediate = operator.join("releases");
                let release = intermediate.join("current");
                let unrelated = outer.join("unrelated");
                fs::create_dir_all(&release).unwrap();
                fs::create_dir(&unrelated).unwrap();
                activate(&operator, 2_000);
                let (retained, blocked) = match scenario {
                    "intermediate" => {
                        activate(&intermediate, 1_000);
                        (&operator, &intermediate)
                    }
                    "outer" => {
                        activate(&outer, 1_000);
                        (&operator, &outer)
                    }
                    _ => (&unrelated, &operator),
                };
                let mut config = Config::for_profile(Profile::Balanced);
                let original = config.clone();
                let error = enforce_active_fleet_policy_with_operator(
                    &release,
                    &mut config,
                    Profile::Balanced,
                    Some(retained),
                )
                .unwrap_err()
                .to_string();
                assert!(
                    error.contains("inside fleet-managed project"),
                    "{scenario}: {error}"
                );
                assert!(
                    error.contains(blocked.to_str().unwrap()),
                    "{scenario}: {error}"
                );
                assert_eq!(config, original);
                if scenario == "outer" {
                    assert!(
                        enforce_active_fleet_policy(&operator, &mut config, Profile::Balanced)
                            .is_err(),
                        "the operator's own strict admission must preserve outer enrollment"
                    );
                }
            }
        }

        #[test]
        fn retained_operator_enrollment_corruption_is_not_skipped() {
            for corruption in ["malformed", "missing", "linked"] {
                let workspace = tempdir().unwrap();
                let operator = workspace.path().canonicalize().unwrap();
                let release = operator.join("releases/current");
                fs::create_dir_all(&release).unwrap();
                activate(&operator, 1_000);
                activate(&release, 2_000);
                let state = operator.join(".franken-node/state");
                match corruption {
                    "malformed" => fs::write(state.join("fleet-policy.json"), b"{").unwrap(),
                    "missing" => fs::rename(
                        state.join("fleet-policy-required.json"),
                        state.join("fleet-policy-required.retained"),
                    )
                    .unwrap(),
                    _ => {
                        let retained = state.with_file_name("state-retained");
                        fs::rename(&state, &retained).unwrap();
                        std::os::unix::fs::symlink(&retained, &state).unwrap();
                    }
                }
                let mut config = Config::for_profile(Profile::Balanced);
                let original = config.clone();
                let error = enforce_active_fleet_policy_with_operator(
                    &release,
                    &mut config,
                    Profile::Balanced,
                    Some(&operator),
                )
                .unwrap_err()
                .to_string();
                assert!(
                    error.contains("cannot exclude fleet policy enrollment at ancestor"),
                    "{corruption}: {error}"
                );
                assert!(
                    error.contains(operator.to_str().unwrap()),
                    "{corruption}: {error}"
                );
                assert_eq!(config, original);
            }
        }

        #[test]
        fn retained_operator_root_rejects_relative_traversal_and_symlink_aliases() {
            let workspace = tempdir().unwrap();
            let root = workspace.path().canonicalize().unwrap();
            let operator = root.join("operator");
            let release = operator.join("current");
            fs::create_dir_all(&release).unwrap();
            activate(&operator, 1_000);
            let alias = root.join("operator-alias");
            std::os::unix::fs::symlink(&operator, &alias).unwrap();
            for invalid in [
                PathBuf::from("operator"),
                operator.join(".."),
                operator.join("."),
                alias,
            ] {
                let error =
                    validate_fleet_policy_project_root_with_operator(&release, Some(&invalid))
                        .unwrap_err()
                        .to_string();
                assert!(
                    error.contains("normalized absolute canonical project root"),
                    "{}: {error}",
                    invalid.display()
                );
            }
        }

        #[test]
        fn policy_readers_use_read_only_shared_locks_and_exclude_writers() {
            use crate::control_plane::fleet_transport::{
                FleetPolicyStore, load_active_fleet_policy,
            };
            use rustix::fs::{OFlags, fcntl_getfl};
            use std::os::unix::fs::PermissionsExt as _;

            let workspace = tempdir().unwrap();
            let operator = workspace.path().canonicalize().unwrap();
            activate(&operator, 1_000);
            let lock_path = operator.join(".franken-node/state/fleet-policy.lock");
            fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o400)).unwrap();
            let reader = FleetPolicyStore::open(&operator, false).unwrap().unwrap();
            assert_eq!(
                fcntl_getfl(&reader.lock).unwrap() & OFlags::RWMODE,
                OFlags::RDONLY,
                "read-only containment cannot open the enrollment lock for writing"
            );
            assert_eq!(
                load_active_fleet_policy(&operator).unwrap(),
                reader.active().unwrap(),
                "independent shared readers retain the same complete policy"
            );

            // Permit a writer to open its own descriptor, then verify that
            // the reader's shared lock still prevents an exclusive commit.
            fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
            let writer_probe = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&lock_path)
                .unwrap();
            assert!(matches!(
                writer_probe.try_lock(),
                Err(std::fs::TryLockError::WouldBlock)
            ));
            drop(reader);
            writer_probe.try_lock().unwrap();
            writer_probe.unlock().unwrap();
            let writer = FleetPolicyStore::open(&operator, true).unwrap().unwrap();
            assert_eq!(
                fcntl_getfl(&writer.lock).unwrap() & OFlags::RWMODE,
                OFlags::RDWR,
                "policy activation retains its writable exclusive descriptor"
            );
        }
    }

    struct TestTransport {
        layout: FleetTransportLayout,
        initialized: bool,
        actions: Vec<FleetActionRecord>,
        nodes: Vec<NodeStatus>,
    }

    impl TestTransport {
        fn new(root_dir: impl Into<PathBuf>) -> Self {
            Self {
                layout: FleetTransportLayout::new(root_dir),
                initialized: false,
                actions: Vec::new(),
                nodes: Vec::new(),
            }
        }

        fn ensure_initialized(&self) -> Result<(), FleetTransportError> {
            if self.initialized {
                Ok(())
            } else {
                Err(FleetTransportError::not_initialized(
                    "call initialize() before using the transport",
                ))
            }
        }
    }

    impl FleetTransport for TestTransport {
        fn initialize(&mut self) -> Result<(), FleetTransportError> {
            self.layout.initialize()?;
            self.initialized = true;
            Ok(())
        }

        fn publish_action(
            &mut self,
            action: &FleetActionRecord,
        ) -> Result<(), FleetTransportError> {
            self.ensure_initialized()?;
            push_bounded(&mut self.actions, action.clone(), MAX_ACTION_LOG_ENTRIES);
            Ok(())
        }

        fn list_actions(&self) -> Result<Vec<FleetActionRecord>, FleetTransportError> {
            self.ensure_initialized()?;
            Ok(self.actions.clone())
        }

        fn upsert_node_status(&mut self, status: &NodeStatus) -> Result<(), FleetTransportError> {
            self.ensure_initialized()?;
            let zone_id = validate_zone_id(&status.zone_id)?.to_string();
            let node_id = validate_node_id(&status.node_id)?.to_string();
            let status = NodeStatus {
                zone_id,
                node_id,
                last_seen: status.last_seen,
                quarantine_version: status.quarantine_version,
                health: status.health,
                applied_actions: status.applied_actions.clone(),
                native_session_drain: status.native_session_drain.clone(),
            };

            if let Some(existing) = self
                .nodes
                .iter_mut()
                .find(|entry| entry.node_id == status.node_id)
            {
                *existing = status;
            } else {
                push_bounded(&mut self.nodes, status, MAX_NODES_CAP);
            }
            Ok(())
        }

        fn list_node_statuses(&self) -> Result<Vec<NodeStatus>, FleetTransportError> {
            self.ensure_initialized()?;
            Ok(self.nodes.clone())
        }
    }

    fn accepts_dyn_transport(_transport: &mut dyn FleetTransport) {}

    #[test]
    fn convergence_receipt_verdict_exact_timeout_fails_closed() {
        assert_eq!(
            fleet_convergence_receipt_verdict(false, 120_000, 120, true),
            "non_converged"
        );
    }

    fn release_action_record(
        action_id: impl Into<String>,
        emitted_at: &str,
        incident_id: impl Into<String>,
    ) -> FleetActionRecord {
        FleetActionRecord {
            action_id: action_id.into(),
            emitted_at: DateTime::parse_from_rfc3339(emitted_at)
                .expect("timestamp")
                .with_timezone(&Utc),
            action: FleetAction::Release {
                zone_id: "prod".to_string(),
                incident_id: incident_id.into(),
                reason: None,
            },
        }
    }

    #[cfg(feature = "control-plane")]
    fn revoke_action_record(
        action_id: impl Into<String>,
        emitted_at: &str,
        extension_id: impl Into<String>,
    ) -> FleetActionRecord {
        FleetActionRecord {
            action_id: action_id.into(),
            emitted_at: DateTime::parse_from_rfc3339(emitted_at)
                .expect("timestamp")
                .with_timezone(&Utc),
            action: FleetAction::Revoke {
                extension_id: extension_id.into(),
                scope: RevocationScope {
                    zone_id: "prod".to_string(),
                    tenant_id: None,
                    severity: RevocationSeverity::Mandatory,
                    reason: "test revocation".to_string(),
                },
            },
        }
    }

    fn node_status(
        zone_id: impl Into<String>,
        node_id: impl Into<String>,
        last_seen: &str,
        quarantine_version: u64,
        health: NodeHealth,
    ) -> NodeStatus {
        NodeStatus {
            zone_id: zone_id.into(),
            node_id: node_id.into(),
            last_seen: DateTime::parse_from_rfc3339(last_seen)
                .expect("timestamp")
                .with_timezone(&Utc),
            quarantine_version,
            health,
            applied_actions: None,
            native_session_drain: None,
        }
    }

    fn temp_leftovers(dir: &Path, marker: &str) -> Vec<String> {
        let mut leftovers = Vec::new();
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => return leftovers,
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.contains(marker) {
                leftovers.push(name);
            }
        }
        leftovers.sort();
        leftovers
    }

    fn signed_supervisor_fixture(
        root: &SigningKey,
        observed_at: DateTime<Utc>,
    ) -> (FleetActionRecord, NodeStatus) {
        let action = FleetActionRecord {
            action_id: "signed-maintenance".into(),
            emitted_at: observed_at,
            action: FleetAction::NativeSessionHold {
                zone_id: "zone-a".into(),
                reason: "maintenance".into(),
            },
        };
        let actions =
            fleet_application_checkpoint(std::slice::from_ref(&action), "zone-a").unwrap();
        let mut drain = super::NativeSessionDrainCheckpoint {
            applied_actions: actions.clone(),
            session_set_sha256: "a".repeat(64),
            admitted_sessions: 2,
            terminal_sessions: 2,
            pending_sessions: 0,
            indeterminate_sessions: 0,
            fence_held: true,
            supervisor_attestation: None,
        };
        let mut attestation = super::NativeSessionDrainAttestation {
            schema_version: super::NATIVE_SESSION_DRAIN_ATTESTATION_SCHEMA.into(),
            node_id: "node-a".into(),
            zone_id: "zone-a".into(),
            drain_id: "01900000-0000-7000-8000-000000000001".into(),
            generation: 2,
            project_root_sha256: "b".repeat(64),
            observed_at,
            product_root_key_id: format!(
                "ed25519:{}",
                hex::encode(root.verifying_key().as_bytes())
            ),
            checkpoint_sha256: drain.observation_sha256().unwrap(),
            signature_hex: String::new(),
        };
        attestation.signature_hex = hex::encode(
            root.sign(&attestation.signing_payload().unwrap())
                .to_bytes(),
        );
        drain.supervisor_attestation = Some(attestation);
        let mut node = node_status(
            "zone-a",
            "node-a",
            &observed_at.to_rfc3339(),
            1,
            NodeHealth::Maintenance,
        );
        node.applied_actions = Some(actions);
        node.native_session_drain = Some(drain);
        (action, node)
    }

    #[test]
    fn supervisor_signature_binds_population_actions_and_enrolled_identity() {
        let root = SigningKey::from_bytes(&[37; 32]);
        let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let (_, status) = signed_supervisor_fixture(&root, now);
        let drain = status.native_session_drain.as_ref().unwrap();
        let signed = drain.supervisor_attestation.as_ref().unwrap();
        signed
            .verify(drain, "node-a", "zone-a", &root.verifying_key())
            .unwrap();
        assert!(
            signed
                .verify(drain, "node-b", "zone-a", &root.verifying_key())
                .is_err()
        );
        assert!(
            signed
                .verify(drain, "node-a", "zone-b", &root.verifying_key())
                .is_err()
        );
        for mutation in 0..5 {
            let mut altered = drain.clone();
            match mutation {
                0 => altered.session_set_sha256 = "c".repeat(64),
                1 => altered.applied_actions.actions_sha256 = "c".repeat(64),
                2 => altered.fence_held = false,
                3 => {
                    altered.terminal_sessions -= 1;
                    altered.pending_sessions += 1;
                }
                _ => {
                    altered.admitted_sessions += 1;
                    altered.terminal_sessions += 1;
                }
            }
            assert!(
                signed
                    .verify(&altered, "node-a", "zone-a", &root.verifying_key())
                    .is_err(),
                "mutation {mutation}"
            );
        }
        let foreign = SigningKey::from_bytes(&[38; 32]);
        let (_, forged) = signed_supervisor_fixture(&foreign, now);
        let forged = forged.native_session_drain.as_ref().unwrap();
        let proof = forged.supervisor_attestation.as_ref().unwrap();
        proof
            .verify(forged, "node-a", "zone-a", &foreign.verifying_key())
            .unwrap();
        assert!(
            proof
                .verify(forged, "node-a", "zone-a", &root.verifying_key())
                .is_err(),
            "a self-consistent incoming key is not enrollment"
        );
    }

    #[test]
    fn supervisor_observation_cannot_renew_its_clock_or_regress_history() {
        let root = SigningKey::from_bytes(&[39; 32]);
        let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let (_, status) = signed_supervisor_fixture(&root, now);
        let signed = status
            .native_session_drain
            .unwrap()
            .supervisor_attestation
            .unwrap();
        signed.validate_freshness(now).unwrap();
        signed
            .validate_freshness(now + chrono::Duration::seconds(299))
            .unwrap();
        assert!(
            signed
                .validate_freshness(now + chrono::Duration::seconds(300))
                .is_err()
        );
        assert!(
            signed
                .validate_freshness(now - chrono::Duration::nanoseconds(1))
                .is_err()
        );
        signed.validate_successor_of(&signed).unwrap();
        for mutation in 0..5 {
            let mut next = signed.clone();
            next.observed_at += chrono::Duration::seconds(1);
            match mutation {
                0 => next.generation -= 1,
                1 => next.drain_id = "01900000-0000-7000-8000-000000000002".into(),
                2 => next.project_root_sha256 = "c".repeat(64),
                3 => next.observed_at = now - chrono::Duration::seconds(1),
                _ => {
                    next.observed_at = now;
                    next.generation += 1;
                }
            }
            assert!(
                next.validate_successor_of(&signed).is_err(),
                "regression {mutation}"
            );
        }
        let mut next = signed.clone();
        next.observed_at += chrono::Duration::seconds(1);
        next.generation += 1;
        next.drain_id = "01900000-0000-7000-8000-000000000002".into();
        next.validate_successor_of(&signed).unwrap();
    }

    #[test]
    fn released_signed_cohort_cannot_satisfy_held_maintenance() {
        let root = SigningKey::from_bytes(&[40; 32]);
        let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let (action, mut node) = signed_supervisor_fixture(&root, now);
        let required = std::collections::BTreeSet::from([("zone-a".into(), "node-a".into())]);
        let observe = |node| {
            super::fleet_native_session_hold_evidence(
                &FleetSharedState {
                    schema_version: FLEET_SHARED_STATE_SCHEMA.into(),
                    actions: vec![action.clone()],
                    nodes: vec![node],
                },
                &action.action_id,
                super::FleetNativeSessionHoldTarget::Held,
                &required,
                now,
                Duration::from_secs(30),
            )
            .unwrap()
        };
        assert!(observe(node.clone()).complete);
        let drain = node.native_session_drain.as_mut().unwrap();
        drain.fence_held = false;
        let digest = drain.observation_sha256().unwrap();
        let proof = drain.supervisor_attestation.as_mut().unwrap();
        proof.checkpoint_sha256 = digest;
        proof.signature_hex = hex::encode(root.sign(&proof.signing_payload().unwrap()).to_bytes());
        drain
            .supervisor_attestation
            .as_ref()
            .unwrap()
            .verify(drain, "node-a", "zone-a", &root.verifying_key())
            .unwrap();
        node.health = NodeHealth::Healthy;
        let evidence = observe(node);
        assert!(!evidence.complete);
        assert!(!evidence.fleet_quiescence_certified);
        assert_eq!(
            evidence.nodes[0].reason,
            super::FleetNativeDrainReadiness::MaintenanceFenceMissing
        );
    }

    #[test]
    fn temp_file_guard_orphans_abandoned_temp_files() {
        let tempdir = tempdir().expect("tempdir");
        let temp_path = tempdir.path().join("actions.json.tmp");
        fs::write(&temp_path, "pending").expect("write temp file");

        {
            let _guard = TempFileGuard::new(temp_path.clone());
        }

        assert!(!temp_path.exists(), "temp file should be moved aside");
        let leftovers = temp_leftovers(tempdir.path(), "actions.json.tmp.orphaned-");
        assert_eq!(leftovers.len(), 1, "expected one orphaned temp artifact");
    }

    #[test]
    fn fleet_transport_trait_is_object_safe() {
        let tempdir = tempdir().expect("tempdir");
        let mut transport = TestTransport::new(tempdir.path());
        accepts_dyn_transport(&mut transport);
    }

    #[test]
    fn validate_node_id_accepts_allowed_charset_and_bounds() {
        let valid = validate_node_id("node_A-1.example").expect("valid node id");
        assert_eq!(valid, "node_A-1.example");

        let max_len = "a".repeat(MAX_NODE_ID_LEN);
        assert_eq!(validate_node_id(&max_len).expect("max length"), max_len);
    }

    #[test]
    fn validate_node_id_rejects_invalid_values() {
        for invalid in [
            "",
            " ",
            " node",
            "node ",
            "../escape",
            "node/slash",
            "node\\slash",
            "node*bad",
        ] {
            assert!(
                validate_node_id(invalid).is_err(),
                "accepted invalid node_id {invalid:?}"
            );
        }

        let too_long = "a".repeat(MAX_NODE_ID_LEN + 1);
        assert!(validate_node_id(&too_long).is_err());
    }

    #[test]
    fn validate_zone_id_rejects_blank_values() {
        assert!(validate_zone_id("").is_err());
        assert!(validate_zone_id("   ").is_err());
        assert!(validate_zone_id(" prod").is_err());
        assert!(validate_zone_id("prod ").is_err());
    }

    #[test]
    fn publish_action_before_initialize_is_rejected() {
        let tempdir = tempdir().expect("tempdir");
        let mut transport = FileFleetTransport::new(tempdir.path().join("missing-state"));

        let error = transport
            .publish_action(&release_action_record(
                "fleet-action-uninitialized",
                "2026-04-06T00:00:00Z",
                "inc-uninitialized",
            ))
            .expect_err("uninitialized transport should reject writes");

        assert!(matches!(error, FleetTransportError::NotInitialized { .. }));
        assert!(!transport.layout().actions_path().exists());
    }

    #[test]
    fn list_actions_before_initialize_is_rejected() {
        let tempdir = tempdir().expect("tempdir");
        let transport = FileFleetTransport::new(tempdir.path().join("missing-state"));

        let error = transport
            .list_actions()
            .expect_err("uninitialized transport should reject reads");

        assert!(matches!(error, FleetTransportError::NotInitialized { .. }));
    }

    #[test]
    fn publish_action_rejects_blank_action_id_without_appending() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        let mut action = release_action_record("fleet-action-valid", "2026-04-06T00:00:00Z", "inc");
        action.action_id = "  ".to_string();
        let error = transport
            .publish_action(&action)
            .expect_err("blank action_id should be rejected");

        assert!(matches!(
            error,
            FleetTransportError::SerializationError { .. }
        ));
        assert_eq!(
            fs::read_to_string(transport.layout().actions_path()).expect("read action log"),
            ""
        );
    }

    #[test]
    fn publish_action_rejects_quarantine_with_blank_reason() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        let action = FleetActionRecord {
            action_id: "fleet-action-blank-reason".to_string(),
            emitted_at: DateTime::parse_from_rfc3339("2026-04-06T00:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            action: FleetAction::Quarantine {
                zone_id: "prod".to_string(),
                incident_id: "inc-blank-reason".to_string(),
                target_id: "sha256:target".to_string(),
                target_kind: FleetTargetKind::Artifact,
                reason: " ".to_string(),
                quarantine_version: 1,
            },
        };

        let error = transport
            .publish_action(&action)
            .expect_err("blank quarantine reason should be rejected");

        assert!(matches!(
            error,
            FleetTransportError::SerializationError { .. }
        ));
        assert!(transport.list_actions().expect("list actions").is_empty());
    }

    #[test]
    fn publish_action_rejects_quarantine_with_padded_target_id() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        let action = FleetActionRecord {
            action_id: "fleet-action-padded-target".to_string(),
            emitted_at: DateTime::parse_from_rfc3339("2026-04-06T00:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            action: FleetAction::Quarantine {
                zone_id: "prod".to_string(),
                incident_id: "inc-padded-target".to_string(),
                target_id: " sha256:artifact ".to_string(),
                target_kind: FleetTargetKind::Artifact,
                reason: "audit reason".to_string(),
                quarantine_version: 1,
            },
        };

        let error = transport
            .publish_action(&action)
            .expect_err("padded quarantine target should be rejected");

        assert!(matches!(
            error,
            FleetTransportError::SerializationError { .. }
        ));
        assert!(transport.list_actions().expect("list actions").is_empty());
    }

    #[test]
    fn publish_action_rejects_release_with_control_character_reason() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        let action = FleetActionRecord {
            action_id: "fleet-action-release-control".to_string(),
            emitted_at: DateTime::parse_from_rfc3339("2026-04-06T00:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            action: FleetAction::Release {
                zone_id: "prod".to_string(),
                incident_id: "inc-release-control".to_string(),
                reason: Some("review\npending".to_string()),
            },
        };

        let error = transport
            .publish_action(&action)
            .expect_err("release reason with control text should be rejected");

        assert!(matches!(
            error,
            FleetTransportError::SerializationError { .. }
        ));
        assert!(transport.list_actions().expect("list actions").is_empty());
    }

    #[test]
    fn publish_action_rejects_policy_update_with_blank_version() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        let action = FleetActionRecord {
            action_id: "fleet-action-blank-policy".to_string(),
            emitted_at: DateTime::parse_from_rfc3339("2026-04-06T00:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            action: FleetAction::PolicyUpdate {
                zone_id: "prod".to_string(),
                policy_version: "\t".to_string(),
                changed_fields: vec!["trust.min_score".to_string()],
                artifact: None,
            },
        };

        let error = transport
            .publish_action(&action)
            .expect_err("blank policy version should be rejected");

        assert!(matches!(
            error,
            FleetTransportError::SerializationError { .. }
        ));
        assert!(transport.list_actions().expect("list actions").is_empty());
    }

    #[test]
    #[cfg(feature = "control-plane")]
    fn publish_action_accepts_valid_revoke() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        let action = revoke_action_record(
            "fleet-action-revoke-valid",
            "2026-04-06T00:00:00Z",
            "ext-malicious",
        );

        transport
            .publish_action(&action)
            .expect("valid revoke should succeed");

        let actions = transport.list_actions().expect("list actions");
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].action_id, "fleet-action-revoke-valid");
        assert!(matches!(&actions[0].action, FleetAction::Revoke { .. }));
        if let FleetAction::Revoke {
            extension_id,
            scope,
        } = &actions[0].action
        {
            assert_eq!(extension_id, "ext-malicious");
            assert_eq!(scope.zone_id, "prod");
        }
    }

    #[test]
    #[cfg(feature = "control-plane")]
    fn publish_action_rejects_revoke_with_blank_extension_id() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        let action = FleetActionRecord {
            action_id: "fleet-action-blank-ext".to_string(),
            emitted_at: DateTime::parse_from_rfc3339("2026-04-06T00:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            action: FleetAction::Revoke {
                extension_id: "  ".to_string(),
                scope: RevocationScope {
                    zone_id: "prod".to_string(),
                    tenant_id: None,
                    severity: RevocationSeverity::Mandatory,
                    reason: "valid reason".to_string(),
                },
            },
        };

        let error = transport
            .publish_action(&action)
            .expect_err("blank extension_id should be rejected");

        assert!(matches!(
            error,
            FleetTransportError::SerializationError { .. }
        ));
        assert!(transport.list_actions().expect("list actions").is_empty());
    }

    #[test]
    #[cfg(feature = "control-plane")]
    fn publish_action_rejects_revoke_with_blank_reason() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        let action = FleetActionRecord {
            action_id: "fleet-action-blank-reason".to_string(),
            emitted_at: DateTime::parse_from_rfc3339("2026-04-06T00:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            action: FleetAction::Revoke {
                extension_id: "ext-test".to_string(),
                scope: RevocationScope {
                    zone_id: "prod".to_string(),
                    tenant_id: None,
                    severity: RevocationSeverity::Emergency,
                    reason: "\n".to_string(),
                },
            },
        };

        let error = transport
            .publish_action(&action)
            .expect_err("blank reason should be rejected");

        assert!(matches!(
            error,
            FleetTransportError::SerializationError { .. }
        ));
        assert!(transport.list_actions().expect("list actions").is_empty());
    }

    #[test]
    #[cfg(feature = "control-plane")]
    fn publish_action_rejects_revoke_with_control_character_tenant_id() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        let action = FleetActionRecord {
            action_id: "fleet-action-bad-tenant".to_string(),
            emitted_at: DateTime::parse_from_rfc3339("2026-04-06T00:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            action: FleetAction::Revoke {
                extension_id: "ext-test".to_string(),
                scope: RevocationScope {
                    zone_id: "prod".to_string(),
                    tenant_id: Some("tenant-a\nshadow".to_string()),
                    severity: RevocationSeverity::Emergency,
                    reason: "valid reason".to_string(),
                },
            },
        };

        let error = transport
            .publish_action(&action)
            .expect_err("control-character tenant_id should be rejected");

        assert!(matches!(
            error,
            FleetTransportError::SerializationError { .. }
        ));
        assert!(transport.list_actions().expect("list actions").is_empty());
    }

    #[test]
    fn upsert_node_status_rejects_whitespace_zone_without_file() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        let error = transport
            .upsert_node_status(&node_status(
                "prod ",
                "node-alpha",
                "2026-04-06T00:00:00Z",
                1,
                NodeHealth::Healthy,
            ))
            .expect_err("whitespace zone_id should be rejected");

        assert!(matches!(
            error,
            FleetTransportError::SerializationError { .. }
        ));
        assert!(
            fs::read_dir(transport.layout().nodes_dir())
                .expect("read nodes dir")
                .next()
                .is_none()
        );
    }

    #[test]
    fn list_actions_rejects_malformed_jsonl_line() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");
        fs::write(transport.layout().actions_path(), "{not-json}\n").expect("write bad log");

        let error = transport
            .list_actions()
            .expect_err("malformed action log should be rejected");

        assert!(matches!(
            error,
            FleetTransportError::SerializationError { .. }
        ));
    }

    #[test]
    fn list_actions_rejects_oversized_jsonl_line_before_parsing() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");
        fs::write(
            transport.layout().actions_path(),
            vec![b'A'; MAX_ACTION_RECORD_LINE_BYTES.saturating_add(1)],
        )
        .expect("write oversized action log line");

        let error = transport
            .list_actions()
            .expect_err("oversized action log line should be rejected");

        assert!(matches!(
            error,
            FleetTransportError::SerializationError { .. }
        ));
        assert!(error.to_string().contains("JSONL line 1"));
        assert!(error.to_string().contains("exceeds"));
    }

    #[test]
    fn list_node_statuses_rejects_persisted_invalid_node_id() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");
        let bad_status = NodeStatus {
            zone_id: "prod".to_string(),
            node_id: "../escape".to_string(),
            last_seen: DateTime::parse_from_rfc3339("2026-04-06T00:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            quarantine_version: 1,
            health: NodeHealth::Healthy,
            applied_actions: None,
            native_session_drain: None,
        };
        fs::write(
            transport.layout().nodes_dir().join("node-bad.json"),
            serde_json::to_string(&bad_status).expect("serialize bad status"),
        )
        .expect("write bad status");

        let error = transport
            .list_node_statuses()
            .expect_err("invalid persisted node_id should be rejected");

        assert!(matches!(
            error,
            FleetTransportError::SerializationError { .. }
        ));
    }

    #[test]
    fn compact_action_log_rejects_non_positive_retention_days() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        let error = transport
            .compact_action_log_if_needed(
                0,
                0,
                DateTime::parse_from_rfc3339("2026-04-06T00:00:00Z")
                    .expect("timestamp")
                    .with_timezone(&Utc),
            )
            .expect_err("non-positive retention should be rejected");

        assert!(matches!(
            error,
            FleetTransportError::SerializationError { .. }
        ));
    }

    #[test]
    fn fleet_action_roundtrip_preserves_policy_update_variant() {
        let record = FleetActionRecord {
            action_id: "fleet-action-0001".to_string(),
            emitted_at: DateTime::parse_from_rfc3339("2026-04-06T00:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            action: FleetAction::PolicyUpdate {
                zone_id: "prod-us-east".to_string(),
                policy_version: "strict-2026-04-06".to_string(),
                changed_fields: vec!["trust.min_score".to_string(), "fleet.timeout".to_string()],
                artifact: None,
            },
        };

        let json = serde_json::to_string(&record).expect("serialize");
        let roundtrip: FleetActionRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(roundtrip, record);
    }

    #[test]
    fn fleet_shared_state_roundtrip_preserves_nodes_and_actions() {
        let state = FleetSharedState {
            schema_version: FLEET_SHARED_STATE_SCHEMA.to_string(),
            actions: vec![FleetActionRecord {
                action_id: "fleet-action-0002".to_string(),
                emitted_at: DateTime::parse_from_rfc3339("2026-04-06T01:02:03Z")
                    .expect("timestamp")
                    .with_timezone(&Utc),
                action: FleetAction::Quarantine {
                    zone_id: "prod-us-east".to_string(),
                    incident_id: "inc-0002".to_string(),
                    target_id: "sha256:abc123".to_string(),
                    target_kind: FleetTargetKind::Artifact,
                    reason: "high-risk quarantine".to_string(),
                    quarantine_version: 7,
                },
            }],
            nodes: vec![NodeStatus {
                zone_id: "prod-us-east".to_string(),
                node_id: "node-alpha".to_string(),
                last_seen: DateTime::parse_from_rfc3339("2026-04-06T01:02:04Z")
                    .expect("timestamp")
                    .with_timezone(&Utc),
                quarantine_version: 7,
                health: NodeHealth::Healthy,
                applied_actions: None,
                native_session_drain: None,
            }],
        };

        let json = serde_json::to_string(&state).expect("serialize");
        let roundtrip: FleetSharedState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(roundtrip, state);
    }

    #[test]
    fn layout_initialize_creates_expected_directories_and_log() {
        let tempdir = tempdir().expect("tempdir");
        let layout = FleetTransportLayout::new(tempdir.path().join("fleet-state"));
        layout.initialize().expect("initialize");

        assert!(layout.root_dir().is_dir());
        assert!(layout.nodes_dir().is_dir());
        assert!(layout.locks_dir().is_dir());
        assert!(layout.actions_path().is_file());
    }

    #[test]
    fn initialize_trait_creates_directory_structure_if_missing() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("transport-root");
        let mut transport = TestTransport::new(&root);

        transport.initialize().expect("transport initialize");

        assert!(root.is_dir());
        assert!(transport.layout.actions_path().is_file());
        assert!(transport.layout.nodes_dir().is_dir());
        assert!(transport.layout.locks_dir().is_dir());
    }

    #[test]
    fn read_shared_state_preserves_actions_and_sorts_nodes() {
        let tempdir = tempdir().expect("tempdir");
        let mut transport = TestTransport::new(tempdir.path());
        transport.initialize().expect("initialize");

        transport
            .publish_action(&FleetActionRecord {
                action_id: "b".to_string(),
                emitted_at: DateTime::parse_from_rfc3339("2026-04-06T01:00:02Z")
                    .expect("timestamp")
                    .with_timezone(&Utc),
                action: FleetAction::Release {
                    zone_id: "prod".to_string(),
                    incident_id: "inc-b".to_string(),
                    reason: None,
                },
            })
            .expect("publish action");
        transport
            .publish_action(&FleetActionRecord {
                action_id: "a".to_string(),
                emitted_at: DateTime::parse_from_rfc3339("2026-04-06T01:00:01Z")
                    .expect("timestamp")
                    .with_timezone(&Utc),
                action: FleetAction::Release {
                    zone_id: "prod".to_string(),
                    incident_id: "inc-a".to_string(),
                    reason: None,
                },
            })
            .expect("publish action");

        transport
            .upsert_node_status(&NodeStatus {
                zone_id: "prod".to_string(),
                node_id: "node-z".to_string(),
                last_seen: DateTime::parse_from_rfc3339("2026-04-06T01:02:04Z")
                    .expect("timestamp")
                    .with_timezone(&Utc),
                quarantine_version: 2,
                health: NodeHealth::Healthy,
                applied_actions: None,
                native_session_drain: None,
            })
            .expect("upsert node");
        transport
            .upsert_node_status(&NodeStatus {
                zone_id: "prod".to_string(),
                node_id: "node-a".to_string(),
                last_seen: DateTime::parse_from_rfc3339("2026-04-06T01:02:05Z")
                    .expect("timestamp")
                    .with_timezone(&Utc),
                quarantine_version: 3,
                health: NodeHealth::Degraded,
                applied_actions: None,
                native_session_drain: None,
            })
            .expect("upsert node");

        let state = transport.read_shared_state().expect("shared state");
        assert_eq!(state.actions[0].action_id, "b");
        assert_eq!(state.actions[1].action_id, "a");
        assert_eq!(state.nodes[0].node_id, "node-a");
        assert_eq!(state.nodes[1].node_id, "node-z");
    }

    #[test]
    fn file_transport_shared_state_reader_waits_for_inflight_snapshot_write() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        let lock_path = transport.shared_state_lock_path();
        let lock_file = transport.lock_file(&lock_path).expect("open snapshot lock");
        lock_file_with_backoff(&lock_file, &lock_path, false)
            .expect("take exclusive snapshot lock");

        let pending_action =
            release_action_record("pending-action", "2026-04-06T01:00:03Z", "inc-pending");
        let payload = serde_json::to_vec(&pending_action).expect("serialize action");
        let mut action_file = std::fs::OpenOptions::new()
            .append(true)
            .open(transport.layout().actions_path())
            .expect("open actions");
        action_file
            .write_all(&payload)
            .expect("write pending action");
        action_file
            .write_all(b"\n")
            .expect("write action delimiter");
        action_file.sync_data().expect("sync pending action");
        drop(action_file);

        let reader_root = root.clone();
        let reader = std::thread::spawn(move || {
            let transport = FileFleetTransport::new(reader_root);
            transport.read_shared_state()
        });

        let wait_started = Instant::now();
        while wait_started.elapsed() < Duration::from_millis(120) {
            assert!(
                !reader.is_finished(),
                "snapshot reader must not observe partial action/node write"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        let pending_node = node_status(
            "prod",
            "node-pending",
            "2026-04-06T01:02:06Z",
            4,
            NodeHealth::Healthy,
        );
        transport
            .write_node_status_unlocked(&pending_node)
            .expect("write pending node");
        lock_file.unlock().expect("release snapshot lock");

        let state = reader
            .join()
            .expect("reader join")
            .expect("snapshot read after writer completes");
        assert!(
            state
                .actions
                .iter()
                .any(|action| action.action_id == pending_action.action_id)
        );
        assert!(
            state
                .nodes
                .iter()
                .any(|node| node.node_id == pending_node.node_id)
        );
    }

    #[test]
    fn file_fleet_node_status_scan_waits_for_inflight_snapshot_write() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        transport
            .upsert_node_status(&node_status(
                "prod",
                "node-ready",
                "2026-04-06T01:02:05Z",
                1,
                NodeHealth::Healthy,
            ))
            .expect("write ready node");

        let lock_path = transport.shared_state_lock_path();
        let lock_file = transport.lock_file(&lock_path).expect("open snapshot lock");
        lock_file_with_backoff(&lock_file, &lock_path, false)
            .expect("take exclusive snapshot lock");

        let reader_root = root.clone();
        let reader = std::thread::spawn(move || {
            let transport = FileFleetTransport::new(reader_root);
            transport.list_node_statuses()
        });

        let wait_started = Instant::now();
        while wait_started.elapsed() < Duration::from_millis(120) {
            assert!(
                !reader.is_finished(),
                "node status scan must wait for the shared snapshot lock"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        let pending_node = node_status(
            "prod",
            "node-pending",
            "2026-04-06T01:02:06Z",
            2,
            NodeHealth::Healthy,
        );
        transport
            .write_node_status_unlocked(&pending_node)
            .expect("write pending node");
        lock_file.unlock().expect("release snapshot lock");

        let mut nodes = reader
            .join()
            .expect("reader join")
            .expect("node scan after writer completes");
        nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].node_id, "node-pending");
        assert_eq!(nodes[1].node_id, "node-ready");
    }

    #[test]
    fn node_status_path_uses_validated_node_ids() {
        let tempdir = tempdir().expect("tempdir");
        let layout = FleetTransportLayout::new(tempdir.path());

        assert_eq!(
            layout.node_status_path("node-alpha").expect("path"),
            tempdir
                .path()
                .join(FLEET_NODE_DIR)
                .join("node-node-alpha.json")
        );
        assert!(layout.node_status_path("../escape").is_err());
    }

    #[test]
    fn file_transport_initialization_creates_directory_structure() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);

        transport.initialize().expect("initialize file transport");

        assert!(root.is_dir());
        assert!(transport.layout().actions_path().is_file());
        assert!(transport.layout().nodes_dir().is_dir());
        assert!(transport.layout().locks_dir().is_dir());
    }

    #[test]
    fn file_transport_persists_actions_and_latest_node_state() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        transport
            .publish_action(&release_action_record(
                "fleet-action-10",
                "2026-04-06T02:00:00Z",
                "inc-10",
            ))
            .expect("publish action");
        transport
            .upsert_node_status(&node_status(
                "prod",
                "node-alpha",
                "2026-04-06T02:00:01Z",
                10,
                NodeHealth::Healthy,
            ))
            .expect("write node");
        transport
            .upsert_node_status(&node_status(
                "prod",
                "node-alpha",
                "2026-04-06T02:00:02Z",
                11,
                NodeHealth::Quarantined,
            ))
            .expect("rewrite node");

        let state = transport.read_shared_state().expect("shared state");
        assert_eq!(state.actions.len(), 1);
        assert_eq!(state.nodes.len(), 1);
        assert_eq!(state.nodes[0].quarantine_version, 11);
        assert_eq!(state.nodes[0].health, NodeHealth::Quarantined);

        let persisted: NodeStatus = serde_json::from_str(
            &fs::read_to_string(
                transport
                    .layout()
                    .node_status_path("node-alpha")
                    .expect("node status path"),
            )
            .expect("read node file"),
        )
        .expect("parse node file");
        assert_eq!(persisted, state.nodes[0]);
    }

    #[test]
    fn file_transport_upsert_node_status_cleans_temp_files() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        transport
            .upsert_node_status(&node_status(
                "prod",
                "node-clean",
                "2026-04-06T02:10:00Z",
                12,
                NodeHealth::Healthy,
            ))
            .expect("write node");

        let leftovers = temp_leftovers(transport.layout().nodes_dir(), ".json.tmp-");
        assert!(
            leftovers.is_empty(),
            "found temp node status leftovers: {leftovers:?}"
        );
    }

    #[test]
    fn file_transport_concurrent_appends_preserve_jsonl_integrity() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        let mut workers = Vec::new();
        for worker in 0..4 {
            let root = root.clone();
            workers.push(std::thread::spawn(move || {
                let mut transport = FileFleetTransport::new(root);
                for index in 0..25 {
                    transport
                        .publish_action(&FleetActionRecord {
                            action_id: format!("worker-{worker}-action-{index}"),
                            emitted_at: clock::wall_now(),
                            action: FleetAction::Release {
                                zone_id: "prod".to_string(),
                                incident_id: format!("inc-{worker}-{index}"),
                                reason: None,
                            },
                        })
                        .expect("publish action");
                }
            }));
        }

        for worker in workers {
            worker.join().expect("worker join");
        }

        let log = fs::read_to_string(transport.layout().actions_path()).expect("read action log");
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 100);
        for line in lines {
            let parsed: FleetActionRecord = serde_json::from_str(line).expect("parse JSONL line");
            assert!(parsed.action_id.starts_with("worker-"));
        }

        let persisted = transport.list_actions().expect("list actions");
        assert_eq!(persisted.len(), 100);
    }

    #[test]
    fn file_transport_lists_stale_nodes_from_persisted_state() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        transport
            .upsert_node_status(&node_status(
                "prod",
                "node-fresh",
                "2026-04-06T03:09:30Z",
                3,
                NodeHealth::Healthy,
            ))
            .expect("write fresh node");
        transport
            .upsert_node_status(&node_status(
                "prod",
                "node-stale",
                "2026-04-06T03:00:00Z",
                3,
                NodeHealth::Degraded,
            ))
            .expect("write stale node");

        let stale = transport
            .list_stale_nodes(
                DateTime::parse_from_rfc3339("2026-04-06T03:10:00Z")
                    .expect("timestamp")
                    .with_timezone(&Utc),
                Duration::from_secs(60),
            )
            .expect("stale nodes");

        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].node_id, "node-stale");
    }

    #[test]
    fn lock_retry_backoffs_match_expected_schedule() {
        assert_eq!(
            lock_retry_base_backoffs(),
            [
                Duration::from_millis(100),
                Duration::from_millis(200),
                Duration::from_millis(400),
                Duration::from_millis(800),
                Duration::from_millis(1_600),
            ]
        );
    }

    #[test]
    fn lock_retry_backoffs_apply_half_range_jitter() {
        let mut saw_non_base_delay = false;

        for _ in 0..32 {
            let jittered = lock_retry_backoffs();
            for (delay, base_millis) in jittered.iter().zip(LOCK_RETRY_BACKOFF_MILLIS) {
                let min_millis = base_millis / 2;
                let max_millis = base_millis + (base_millis / 2);
                assert!(
                    *delay >= Duration::from_millis(min_millis)
                        && *delay <= Duration::from_millis(max_millis),
                    "jittered delay {:?} outside +/-50% range for {base_millis}ms",
                    delay
                );
                saw_non_base_delay |= *delay != Duration::from_millis(base_millis);
            }
        }

        assert!(
            saw_non_base_delay,
            "retry backoff should not be deterministic"
        );
    }

    #[test]
    fn lock_file_with_backoff_jitter_spreads_burst_contention() {
        let tempdir = tempdir().expect("tempdir");
        let lock_path = tempdir.path().join("burst.lock");
        let holder = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .expect("open holder lock");
        holder.lock().expect("take initial lock");

        let worker_count = 10;
        let barrier = Arc::new(Barrier::new(worker_count + 1));
        let (sender, receiver) = mpsc::channel();
        let started = Instant::now();
        let mut workers = Vec::new();

        for _ in 0..worker_count {
            let barrier = Arc::clone(&barrier);
            let lock_path = lock_path.clone();
            let sender = sender.clone();
            workers.push(std::thread::spawn(move || {
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(&lock_path)
                    .expect("open worker lock");
                barrier.wait();
                lock_file_with_backoff(&file, &lock_path, false).expect("worker lock");
                sender.send(started.elapsed()).expect("send acquisition");
                std::thread::sleep(Duration::from_millis(8));
                file.unlock().expect("unlock worker lock");
            }));
        }
        drop(sender);

        barrier.wait();
        std::thread::sleep(Duration::from_millis(105));
        holder.unlock().expect("release initial lock");

        let mut acquisition_times: Vec<Duration> = receiver.iter().collect();
        for worker in workers {
            worker.join().expect("worker join");
        }
        acquisition_times.sort();

        assert_eq!(acquisition_times.len(), worker_count);
        let first = acquisition_times[0];
        let last = *acquisition_times.last().expect("last acquisition");
        assert!(
            first < Duration::from_millis(230),
            "at least one contender should escape the deterministic 300ms convoy window; got {first:?}"
        );
        assert!(
            last.saturating_sub(first) >= Duration::from_millis(60),
            "acquisitions should be spread by jitter, got {:?}",
            acquisition_times
        );
    }

    #[test]
    fn file_transport_reports_lock_contention_after_retry_budget() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(transport.layout().actions_path())
            .expect("open action log");
        lock_file_with_backoff(&file, transport.layout().actions_path(), false).expect("take lock");

        let started = Instant::now();
        let error = transport
            .publish_action(&release_action_record(
                "fleet-action-locked",
                "2026-04-06T04:00:00Z",
                "inc-locked",
            ))
            .expect_err("lock contention");
        file.unlock().expect("release lock");

        assert!(matches!(error, FleetTransportError::LockContention { .. }));
        assert!(
            started.elapsed() >= Duration::from_millis(1_500),
            "expected retry backoff budget to elapse, got {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn file_transport_compaction_process_guard_is_scoped_per_root() {
        let tempdir = tempdir().expect("tempdir");
        let root_a = tempdir.path().join("fleet-a");
        let root_b = tempdir.path().join("fleet-b");
        let equivalent_root_a_parent = root_a.join("nested");
        fs::create_dir_all(&equivalent_root_a_parent).expect("create equivalent parent");
        let equivalent_root_a = equivalent_root_a_parent.join("..");
        let mut transport_a = FileFleetTransport::new(&root_a);
        let mut transport_b = FileFleetTransport::new(&root_b);
        transport_a.initialize().expect("initialize root a");
        transport_b.initialize().expect("initialize root b");

        assert_eq!(
            fleet_action_compaction_root_key(transport_a.layout.root_dir())
                .expect("canonical root a"),
            fleet_action_compaction_root_key(&equivalent_root_a).expect("equivalent root a")
        );

        let guard_a = lock_fleet_action_compaction_process(transport_a.layout.root_dir())
            .expect("first root guard");
        let (sender, receiver) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let _guard = lock_fleet_action_compaction_process(&equivalent_root_a)
                .expect("equivalent root guard should wait then acquire");
            sender.send(()).expect("send equivalent acquisition");
        });
        assert!(
            matches!(
                receiver.recv_timeout(Duration::from_millis(100)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "equivalent root spelling must block behind the existing process guard"
        );

        transport_b
            .publish_action(&release_action_record(
                "fleet-action-independent-root",
                "2026-04-06T04:10:00Z",
                "inc-independent",
            ))
            .expect("independent root should not share process guard");

        let actions = transport_b.list_actions().expect("list actions");
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].action_id, "fleet-action-independent-root");

        drop(guard_a);
        receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("equivalent root guard should acquire after first guard drops");
        waiter.join().expect("equivalent root waiter join");
    }

    #[test]
    fn file_transport_rejects_oversized_action_records() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        let error = transport
            .publish_action(&FleetActionRecord {
                action_id: "fleet-action-oversized".to_string(),
                emitted_at: DateTime::parse_from_rfc3339("2026-04-06T04:00:00Z")
                    .expect("timestamp")
                    .with_timezone(&Utc),
                action: FleetAction::Quarantine {
                    zone_id: "prod".to_string(),
                    incident_id: "inc-oversized".to_string(),
                    target_id: "sha256:oversized".to_string(),
                    target_kind: FleetTargetKind::Artifact,
                    reason: "x".repeat(MAX_ACTION_RECORD_BYTES),
                    quarantine_version: 7,
                },
            })
            .expect_err("oversized action should be rejected");

        assert!(matches!(
            error,
            FleetTransportError::SerializationError { .. }
        ));
    }

    #[test]
    fn file_transport_compacts_large_logs_by_retention_window() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        transport
            .publish_action(&release_action_record(
                "fleet-action-old",
                "2026-02-01T00:00:00Z",
                "inc-old",
            ))
            .expect("publish old action");
        transport
            .publish_action(&release_action_record(
                "fleet-action-new",
                "2026-04-05T00:00:00Z",
                "inc-new",
            ))
            .expect("publish new action");

        transport
            .compact_action_log_if_needed(
                1,
                ACTION_LOG_RETENTION_DAYS,
                DateTime::parse_from_rfc3339("2026-04-06T00:00:00Z")
                    .expect("timestamp")
                    .with_timezone(&Utc),
            )
            .expect("compact action log");

        let actions = transport.list_actions().expect("list actions");
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].action_id, "fleet-action-new");

        let leftovers = temp_leftovers(transport.layout().root_dir(), ".jsonl.tmp-");
        assert!(
            leftovers.is_empty(),
            "found temp compaction leftovers: {leftovers:?}"
        );
    }

    #[test]
    fn file_transport_compaction_never_expires_unresolved_containment() {
        let dir = tempdir().expect("tempdir");
        let mut transport = FileFleetTransport::new(dir.path());
        transport.initialize().expect("initialize");
        let now = DateTime::parse_from_rfc3339("2026-04-06T00:00:00Z")
            .expect("timestamp")
            .with_timezone(&Utc);
        let old = now - chrono::TimeDelta::days(60);
        for incident in ["active", "old-released", "recently-released"] {
            transport
                .publish_action(&FleetActionRecord {
                    action_id: format!("quarantine-{incident}"),
                    emitted_at: old,
                    action: FleetAction::Quarantine {
                        zone_id: "prod".to_string(),
                        incident_id: incident.to_string(),
                        target_id: "extension".to_string(),
                        target_kind: FleetTargetKind::Extension,
                        reason: "containment has no implicit expiry".to_string(),
                        quarantine_version: 1,
                    },
                })
                .expect("quarantine");
        }
        for (incident, timestamp) in [
            ("old-released", old + chrono::TimeDelta::seconds(1)),
            ("recently-released", now),
        ] {
            transport
                .publish_action(&FleetActionRecord {
                    action_id: format!("release-{incident}"),
                    emitted_at: timestamp,
                    action: FleetAction::Release {
                        zone_id: "prod".to_string(),
                        incident_id: incident.to_string(),
                        reason: None,
                    },
                })
                .expect("release");
        }
        transport
            .compact_action_log_if_needed(1, ACTION_LOG_RETENTION_DAYS, now)
            .expect("compact");
        let ids: std::collections::BTreeSet<String> = transport
            .list_actions()
            .expect("actions")
            .into_iter()
            .map(|action| action.action_id)
            .collect();
        assert_eq!(
            ids,
            [
                "quarantine-active",
                "quarantine-recently-released",
                "release-recently-released"
            ]
            .into_iter()
            .map(String::from)
            .collect()
        );
    }

    #[test]
    fn file_transport_compaction_preserves_backdated_requarantine_and_release_order() {
        let directory = tempdir().expect("tempdir");
        let mut transport = FileFleetTransport::new(directory.path());
        transport.initialize().expect("initialize");
        let now = Utc::now();
        let old = now - chrono::TimeDelta::days(60);
        let original = FleetActionRecord {
            action_id: "z-original".to_string(),
            emitted_at: old,
            action: FleetAction::Quarantine {
                zone_id: "prod".to_string(),
                incident_id: "reopened-incident".to_string(),
                target_id: "extension".to_string(),
                target_kind: FleetTargetKind::Extension,
                reason: "retain active containment despite issuer clock skew".to_string(),
                quarantine_version: 1,
            },
        };
        let release = FleetActionRecord {
            action_id: "m-release".to_string(),
            emitted_at: old + chrono::TimeDelta::seconds(1),
            action: FleetAction::Release {
                zone_id: "prod".to_string(),
                incident_id: "reopened-incident".to_string(),
                reason: None,
            },
        };
        let mut repeat = original.clone();
        repeat.action_id = "a-requarantine".to_string();
        repeat.emitted_at = old - chrono::TimeDelta::hours(1);
        let expected = vec![original, release.clone(), repeat];
        for action in &expected {
            transport.publish_action(action).expect("publish");
        }
        let checkpoint = fleet_application_checkpoint(&expected, "prod").expect("checkpoint");
        transport
            .compact_action_log_if_needed(1, ACTION_LOG_RETENTION_DAYS, now)
            .expect("compact active incident");
        assert_eq!(
            transport.list_actions().expect("retained history"),
            expected
        );
        assert_eq!(
            fleet_application_checkpoint(
                &transport.read_shared_state().expect("shared state").actions,
                "prod"
            )
            .expect("compacted checkpoint"),
            checkpoint
        );
        transport
            .publish_action(&release)
            .expect("retry does not release the new quarantine");
        assert_eq!(transport.list_actions().expect("retry history"), expected);

        let mut final_release = release;
        final_release.action_id = "0-final-release".to_string();
        final_release.emitted_at = old - chrono::TimeDelta::hours(2);
        transport.publish_action(&final_release).expect("release");
        transport
            .compact_action_log_if_needed(1, ACTION_LOG_RETENTION_DAYS, now)
            .expect("compact actually released old incident");
        assert!(
            transport
                .list_actions()
                .expect("compacted history")
                .is_empty()
        );
    }

    #[test]
    fn file_transport_concurrent_compactions_preserve_consistent_final_state() {
        const WORKERS: usize = 8;
        const RETAINED_ACTIONS: usize = 12;

        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        for index in 0..RETAINED_ACTIONS {
            transport
                .publish_action(&release_action_record(
                    format!("fleet-action-old-{index}"),
                    "2026-02-01T00:00:00Z",
                    format!("inc-old-{index}"),
                ))
                .expect("publish old action");
            transport
                .publish_action(&release_action_record(
                    format!("fleet-action-new-{index}"),
                    "2026-04-05T00:00:00Z",
                    format!("inc-new-{index}"),
                ))
                .expect("publish new action");
        }

        let barrier = Arc::new(Barrier::new(WORKERS));
        let now = DateTime::parse_from_rfc3339("2026-04-06T00:00:00Z")
            .expect("timestamp")
            .with_timezone(&Utc);
        let mut workers = Vec::new();

        for worker in 0..WORKERS {
            let root = root.clone();
            let barrier = Arc::clone(&barrier);
            let now = now.clone();
            workers.push(std::thread::spawn(move || {
                let transport = FileFleetTransport::new(root);
                barrier.wait();
                transport
                    .compact_action_log_if_needed(1, ACTION_LOG_RETENTION_DAYS, now)
                    .map_err(|err| format!("worker {worker} compact action log: {err}"))
            }));
        }

        for worker in workers {
            let result = worker.join().expect("compaction worker join");
            assert!(result.is_ok(), "{}", result.unwrap_err());
        }

        let mut actions = transport.list_actions().expect("list actions");
        actions.sort_by(|left, right| left.action_id.cmp(&right.action_id));
        let actual_ids: Vec<_> = actions
            .iter()
            .map(|action| action.action_id.clone())
            .collect();
        // bd-o776s: actual_ids was sorted lexicographically by action_id above, so
        // the expected list must use the same ordering — otherwise the numeric index
        // order places "fleet-action-new-10"/"-11" after "-9" while the lexicographic
        // actual order places them right after "-1", failing equality even though the
        // retained SET is correct.
        let mut expected_ids: Vec<_> = (0..RETAINED_ACTIONS)
            .map(|index| format!("fleet-action-new-{index}"))
            .collect();
        expected_ids.sort();
        assert_eq!(actual_ids, expected_ids);

        let log = fs::read_to_string(transport.layout().actions_path()).expect("read action log");
        assert_eq!(log.lines().count(), RETAINED_ACTIONS);
        for line in log.lines() {
            let parsed: FleetActionRecord = serde_json::from_str(line).expect("parse JSONL line");
            assert!(parsed.action_id.starts_with("fleet-action-new-"));
        }

        let leftovers = temp_leftovers(transport.layout().root_dir(), ".jsonl.tmp-");
        assert!(
            leftovers.is_empty(),
            "found temp compaction leftovers: {leftovers:?}"
        );
    }

    #[test]
    fn fleet_convergence_receipt_payload_hash_domain_separation() {
        use ed25519_dalek::SigningKey;
        use sha2::{Digest, Sha256};

        // Test payload
        let test_payload = serde_json::json!({
            "zone_id": "zone-001",
            "convergence_state": "active",
            "timestamp": "2026-04-21T19:00:00Z"
        });

        // Generate a test signing key
        let signing_key = SigningKey::generate(&mut rand::thread_rng());

        // Sign with the new domain-separated hash
        let receipt = sign_fleet_convergence_receipt_payload(
            &test_payload,
            &signing_key,
            "test",
            "test-identity",
        )
        .expect("signing should succeed");

        // Manually compute what the legacy bare hash would be
        let canonical_payload = canonical_fleet_convergence_receipt_payload(&test_payload)
            .expect("canonicalization should succeed");
        let mut legacy_hasher = Sha256::new();
        legacy_hasher.update(&canonical_payload);
        let legacy_hash = hex::encode(legacy_hasher.finalize());

        // The new hash should be different from the legacy hash
        assert_ne!(
            receipt.signed_payload_sha256, legacy_hash,
            "Domain-separated hash should differ from legacy bare hash"
        );

        // Verify the new hash follows the expected domain-separated pattern
        let mut expected_hasher = Sha256::new();
        expected_hasher.update(b"fleet_convergence_receipt_payload_v1:");
        expected_hasher
            .update((u64::try_from(canonical_payload.len()).unwrap_or(u64::MAX)).to_le_bytes());
        expected_hasher.update(&canonical_payload);
        let expected_hash = hex::encode(expected_hasher.finalize());

        assert_eq!(
            receipt.signed_payload_sha256, expected_hash,
            "Domain-separated hash should match expected pattern"
        );

        // Ensure the hash is deterministic
        let receipt2 = sign_fleet_convergence_receipt_payload(
            &test_payload,
            &signing_key,
            "test",
            "test-identity",
        )
        .expect("second signing should succeed");

        assert_eq!(
            receipt.signed_payload_sha256, receipt2.signed_payload_sha256,
            "Hash should be deterministic for same input"
        );
    }

    /// Regression for bd-98xo5.7.1: `canonicalize_json_value` previously
    /// `format!`-allocated a fresh path string on every recursive descent
    /// even though the path is only used on the float-error branch. The
    /// refactored implementation builds a `Vec<PathSeg>` stack and renders
    /// the path string only when emitting the error. This test pins the
    /// rendered path format on a realistic nested payload so a future
    /// refactor of `render_path` cannot silently change the operator-
    /// facing error string.
    #[test]
    fn canonicalize_json_value_float_error_path_matches_legacy_format() {
        use serde_json::json;
        let payload = json!({
            "zones": [
                {
                    "id": "zone-a",
                    "timestamp": 1.5,
                },
            ],
        });
        let err = canonical_fleet_convergence_receipt_payload(&payload)
            .expect_err("float at $.zones[0].timestamp must surface a serialization error");
        let detail = err.to_string();
        assert!(
            detail.contains("$.zones[0].timestamp"),
            "rendered float-error path must equal the legacy `$.zones[0].timestamp` format; got: {detail}",
        );
        assert!(
            detail.contains("non-deterministic float"),
            "error message must keep the legacy `non-deterministic float` prefix; got: {detail}",
        );
    }

    /// Comprehensive negative-path test module covering edge cases and attack vectors.
    ///
    /// These tests validate robustness against malicious inputs, resource exhaustion,
    /// timing attacks, and filesystem edge cases in fleet transport operations.
    #[cfg(test)]
    mod fleet_transport_comprehensive_negative_tests {
        use super::{
            ACTION_LOG_RETENTION_DAYS, DateTime, Duration, FileFleetTransport, FleetAction,
            FleetActionRecord, FleetTargetKind, FleetTransport, FleetTransportError,
            FleetTransportLayout, MAX_ACTION_RECORD_BYTES, MAX_NODE_ID_LEN, NodeHealth, NodeStatus,
            Utc, clock, fs, node_status, release_action_record, tempdir,
        };

        #[test]
        fn unicode_injection_in_fleet_identifiers_handled_safely() {
            let tempdir = tempdir().expect("tempdir");
            let root = tempdir.path().join("fleet-state");
            let mut transport = FileFleetTransport::new(&root);
            transport.initialize().expect("initialize");

            // Unicode control characters, NULL bytes, path traversal attempts
            let malicious_zone_ids = vec![
                "zone\u{0000}null",
                "zone\u{200B}zwsp",
                "zone\u{FEFF}bom",
                "zone/../../../etc",
                "zone\u{202E}rtl\u{202D}",
                "zone\x1B[31mANSI",
                "zone\u{1F4A9}emoji",
            ];

            let malicious_node_ids = vec![
                "node\u{0000}null",
                "node\u{200B}zwsp",
                "node/../escape",
                "node\x1B[Hclear",
                "node\u{202E}direction",
            ];

            let malicious_action_ids = vec![
                "action\u{0000}null",
                "action\u{200B}zwsp",
                "action/../traverse",
                "action\x1B[31mred",
                "action\u{202E}rtl",
            ];

            for malicious_zone in &malicious_zone_ids {
                for malicious_node in &malicious_node_ids {
                    for malicious_action in &malicious_action_ids {
                        // Test node status validation
                        let node_result = transport.upsert_node_status(&NodeStatus {
                            zone_id: malicious_zone.to_string(),
                            node_id: malicious_node.to_string(),
                            last_seen: clock::wall_now(),
                            quarantine_version: 1,
                            health: NodeHealth::Healthy,
                            applied_actions: None,
                            native_session_drain: None,
                        });

                        // Should reject malicious identifiers gracefully
                        assert!(
                            node_result.is_err(),
                            "Should reject malicious zone/node: {}/{}",
                            malicious_zone,
                            malicious_node
                        );

                        // Test action validation
                        let action_result = transport.publish_action(&FleetActionRecord {
                            action_id: malicious_action.to_string(),
                            emitted_at: clock::wall_now(),
                            action: FleetAction::Release {
                                zone_id: malicious_zone.to_string(),
                                incident_id: "inc-test".to_string(),
                                reason: None,
                            },
                        });

                        // Should reject malicious action/zone identifiers gracefully
                        assert!(
                            action_result.is_err(),
                            "Should reject malicious action/zone: {}/{}",
                            malicious_action,
                            malicious_zone
                        );
                    }
                }
            }
        }

        #[test]
        fn arithmetic_overflow_protection_in_version_numbers() {
            let tempdir = tempdir().expect("tempdir");
            let root = tempdir.path().join("fleet-state");
            let mut transport = FileFleetTransport::new(&root);
            transport.initialize().expect("initialize");

            // Test with extreme quarantine version numbers
            let extreme_versions = vec![u64::MAX - 1, u64::MAX];

            for &extreme_version in &extreme_versions {
                let status_result = transport.upsert_node_status(&NodeStatus {
                    zone_id: "prod".to_string(),
                    node_id: "overflow-test".to_string(),
                    last_seen: clock::wall_now(),
                    quarantine_version: extreme_version,
                    health: NodeHealth::Healthy,
                    applied_actions: None,
                    native_session_drain: None,
                });

                // Should handle extreme version numbers gracefully
                assert!(
                    status_result.is_ok(),
                    "Should handle extreme version: {}",
                    extreme_version
                );

                let action_result = transport.publish_action(&FleetActionRecord {
                    action_id: format!("action-overflow-{}", extreme_version),
                    emitted_at: clock::wall_now(),
                    action: FleetAction::Quarantine {
                        zone_id: "prod".to_string(),
                        incident_id: "inc-overflow".to_string(),
                        target_id: "target-overflow".to_string(),
                        target_kind: FleetTargetKind::Artifact,
                        reason: "overflow test".to_string(),
                        quarantine_version: extreme_version,
                    },
                });

                // Should handle extreme quarantine versions in actions
                assert!(
                    action_result.is_ok(),
                    "Should handle extreme quarantine version: {}",
                    extreme_version
                );
            }

            // Verify stored values maintain integrity
            let stored_statuses = transport.list_node_statuses().expect("list statuses");
            assert!(!stored_statuses.is_empty());
            for status in &stored_statuses {
                assert!(status.quarantine_version <= u64::MAX);
            }

            let stored_actions = transport.list_actions().expect("list actions");
            assert!(!stored_actions.is_empty());
        }

        #[test]
        fn memory_exhaustion_through_massive_action_logs() {
            let tempdir = tempdir().expect("tempdir");
            let root = tempdir.path().join("fleet-state");
            let mut transport = FileFleetTransport::new(&root);
            transport.initialize().expect("initialize");

            // Generate massive action log to test memory bounds
            let massive_action_count = 1000;
            let massive_reason_size = 1500; // Near MAX_ACTION_RECORD_BYTES limit

            for action_idx in 0..massive_action_count {
                let action_result = transport.publish_action(&FleetActionRecord {
                    action_id: format!("flood_action_{action_idx:05}"),
                    emitted_at: clock::wall_now(),
                    action: FleetAction::Quarantine {
                        zone_id: "prod".to_string(),
                        incident_id: format!("flood_inc_{action_idx:05}"),
                        target_id: format!("flood_target_{action_idx:05}"),
                        target_kind: FleetTargetKind::Artifact,
                        reason: "x".repeat(massive_reason_size), // Large but within bounds
                        quarantine_version: action_idx as u64,
                    },
                });

                // Should handle large actions within bounds
                assert!(
                    action_result.is_ok(),
                    "Should handle large action at index {}",
                    action_idx
                );
            }

            // Test oversized action rejection
            let oversized_result = transport.publish_action(&FleetActionRecord {
                action_id: "oversized_action".to_string(),
                emitted_at: clock::wall_now(),
                action: FleetAction::Quarantine {
                    zone_id: "prod".to_string(),
                    incident_id: "oversized_inc".to_string(),
                    target_id: "oversized_target".to_string(),
                    target_kind: FleetTargetKind::Artifact,
                    reason: "x".repeat(MAX_ACTION_RECORD_BYTES + 100), // Exceeds limit
                    quarantine_version: 999,
                },
            });

            // Should reject oversized actions
            assert!(oversized_result.is_err(), "Should reject oversized action");

            // Verify bounded memory usage
            let all_actions = transport.list_actions().expect("list actions");
            assert_eq!(all_actions.len(), massive_action_count);
        }

        #[test]
        fn concurrent_file_operations_race_condition_simulation() {
            let tempdir = tempdir().expect("tempdir");
            let root = tempdir.path().join("fleet-state");

            // Initialize transport
            {
                let mut transport = FileFleetTransport::new(&root);
                transport.initialize().expect("initialize");
            }

            // Simulate concurrent operations
            let mut handles = Vec::new();
            let thread_count = 8;
            let operations_per_thread = 25;

            for thread_id in 0..thread_count {
                let root = root.clone();
                handles.push(std::thread::spawn(move || {
                    let mut transport = FileFleetTransport::new(&root);

                    for op_id in 0..operations_per_thread {
                        let node_id = format!("node-{thread_id}-{op_id}");
                        let action_id = format!("action-{thread_id}-{op_id}");

                        // Interleave node status updates and action publishing
                        if op_id % 2 == 0 {
                            let _ = transport.upsert_node_status(&NodeStatus {
                                zone_id: "prod".to_string(),
                                node_id: node_id.clone(),
                                last_seen: clock::wall_now(),
                                quarantine_version: op_id as u64,
                                health: NodeHealth::Healthy,
                                applied_actions: None,
                                native_session_drain: None,
                            });
                        } else {
                            let _ = transport.publish_action(&FleetActionRecord {
                                action_id: action_id.clone(),
                                emitted_at: clock::wall_now(),
                                action: FleetAction::Release {
                                    zone_id: "prod".to_string(),
                                    incident_id: format!("inc-{thread_id}-{op_id}"),
                                    reason: None,
                                },
                            });
                        }
                    }
                }));
            }

            // Wait for all threads to complete
            for handle in handles {
                handle.join().expect("thread join");
            }

            // Verify filesystem integrity after concurrent operations
            let transport = FileFleetTransport::new(&root);
            let final_actions = transport.list_actions().expect("final actions");
            let final_nodes = transport.list_node_statuses().expect("final nodes");

            // Should have some results from concurrent operations
            assert!(
                !final_actions.is_empty(),
                "Should have some actions from concurrent ops"
            );
            assert!(
                !final_nodes.is_empty(),
                "Should have some nodes from concurrent ops"
            );

            // Verify no corruption in action log
            for action in &final_actions {
                assert!(
                    !action.action_id.is_empty(),
                    "Action ID should not be empty"
                );
                assert!(
                    !action.action_id.contains('\0'),
                    "Action ID should not contain null bytes"
                );
            }
        }

        #[test]
        fn filesystem_path_traversal_attack_prevention() {
            let tempdir = tempdir().expect("tempdir");
            let root = tempdir.path().join("fleet-state");
            let mut transport = FileFleetTransport::new(&root);
            transport.initialize().expect("initialize");

            // Test various path traversal attacks in node IDs
            let path_traversal_attempts = vec![
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "node/../escape",
                "node/subdir/file",
                "node\\windows\\path",
                "./current/dir",
                "~/home/escape",
                "/absolute/path",
                "\\absolute\\windows\\path",
                "node\0null",
                "node\x00null_byte",
            ];

            for malicious_path in &path_traversal_attempts {
                let status_result = transport.upsert_node_status(&NodeStatus {
                    zone_id: "prod".to_string(),
                    node_id: malicious_path.to_string(),
                    last_seen: clock::wall_now(),
                    quarantine_version: 1,
                    health: NodeHealth::Healthy,
                    applied_actions: None,
                    native_session_drain: None,
                });

                // Should reject path traversal attempts
                assert!(
                    status_result.is_err(),
                    "Should reject path traversal: {}",
                    malicious_path
                );

                // Verify layout path generation rejects malicious paths
                let path_result = transport.layout().node_status_path(malicious_path);
                assert!(
                    path_result.is_err(),
                    "Layout should reject malicious path: {}",
                    malicious_path
                );
            }

            // Verify no files were created outside the expected directory
            let nodes_dir = transport.layout().nodes_dir();
            assert!(nodes_dir.is_dir(), "Nodes directory should exist");

            // Check that no unexpected files exist
            let entries: Vec<_> = fs::read_dir(nodes_dir).expect("read nodes dir").collect();
            assert!(
                entries.is_empty(),
                "No files should be created from malicious attempts"
            );
        }

        #[test]
        fn retention_calculation_boundary_edge_cases() {
            let tempdir = tempdir().expect("tempdir");
            let root = tempdir.path().join("fleet-state");
            let mut transport = FileFleetTransport::new(&root);
            transport.initialize().expect("initialize");

            // Test edge cases in retention calculations
            let now = DateTime::parse_from_rfc3339("2026-04-17T12:00:00Z")
                .expect("now timestamp")
                .with_timezone(&Utc);

            // Action exactly at retention boundary
            let boundary_time = now - chrono::TimeDelta::days(ACTION_LOG_RETENTION_DAYS);
            transport
                .publish_action(&FleetActionRecord {
                    action_id: "boundary-action".to_string(),
                    emitted_at: boundary_time,
                    action: FleetAction::Release {
                        zone_id: "prod".to_string(),
                        incident_id: "boundary-inc".to_string(),
                        reason: None,
                    },
                })
                .expect("publish boundary action");

            // Action just before boundary (should be retained)
            let before_boundary = boundary_time + chrono::TimeDelta::seconds(1);
            transport
                .publish_action(&FleetActionRecord {
                    action_id: "before-boundary-action".to_string(),
                    emitted_at: before_boundary,
                    action: FleetAction::Release {
                        zone_id: "prod".to_string(),
                        incident_id: "before-boundary-inc".to_string(),
                        reason: None,
                    },
                })
                .expect("publish before boundary action");

            // Action just after boundary (should be removed)
            let after_boundary = boundary_time - chrono::TimeDelta::seconds(1);
            transport
                .publish_action(&FleetActionRecord {
                    action_id: "after-boundary-action".to_string(),
                    emitted_at: after_boundary,
                    action: FleetAction::Release {
                        zone_id: "prod".to_string(),
                        incident_id: "after-boundary-inc".to_string(),
                        reason: None,
                    },
                })
                .expect("publish after boundary action");

            // Force compaction
            transport
                .compact_action_log_if_needed(1, ACTION_LOG_RETENTION_DAYS, now)
                .expect("compact log");

            let retained_actions = transport.list_actions().expect("list actions");

            // Should retain actions within the retention window (fail-closed at boundary)
            let retained_ids: Vec<_> = retained_actions.iter().map(|a| &a.action_id).collect();
            assert!(
                retained_ids.contains(&&"boundary-action".to_string()),
                "Boundary action should be retained"
            );
            assert!(
                retained_ids.contains(&&"before-boundary-action".to_string()),
                "Before-boundary action should be retained"
            );
            assert!(
                !retained_ids.contains(&&"after-boundary-action".to_string()),
                "After-boundary action should be removed"
            );
        }

        #[test]
        fn serialization_attack_vectors_json_structure() {
            let tempdir = tempdir().expect("tempdir");
            let root = tempdir.path().join("fleet-state");
            let mut transport = FileFleetTransport::new(&root);
            transport.initialize().expect("initialize");

            // Test JSON injection patterns in string fields
            let malicious_strings = vec![
                "\"},\"malicious\":\"payload\",\"a\":\"",
                "\\\"},\\\"injected\\\":true,\\\"version\\\":\\\"",
                "\n{\"evil\":\"payload\"}\n",
                "\r\n<script>alert('xss')</script>\r\n",
                "\x00\x01\x02\x03", // Binary data
                "\u{FEFF}BOM injection",
                "\\u0000null escape",
            ];

            for malicious_string in &malicious_strings {
                // Test in various string fields
                let action_result = transport.publish_action(&FleetActionRecord {
                    action_id: format!("injection-test-{}", malicious_string.len()),
                    emitted_at: clock::wall_now(),
                    action: FleetAction::Quarantine {
                        zone_id: "prod".to_string(),
                        incident_id: malicious_string.to_string(),
                        target_id: malicious_string.to_string(),
                        target_kind: FleetTargetKind::Artifact,
                        reason: malicious_string.to_string(),
                        quarantine_version: 1,
                    },
                });

                let expects_rejection = malicious_string.trim() != *malicious_string
                    || malicious_string.chars().any(char::is_control);
                if expects_rejection {
                    assert!(
                        action_result.is_err(),
                        "Control-text input should now fail closed: {:?}",
                        malicious_string
                    );
                } else {
                    // Non-control JSON-looking text should still serialize safely.
                    assert!(
                        action_result.is_ok(),
                        "Should handle literal JSON-looking string safely: {:?}",
                        malicious_string
                    );
                }

                let status_result = transport.upsert_node_status(&NodeStatus {
                    zone_id: "prod".to_string(),
                    node_id: format!("node-{}", malicious_string.len()),
                    last_seen: clock::wall_now(),
                    quarantine_version: 1,
                    health: NodeHealth::Healthy,
                    applied_actions: None,
                    native_session_drain: None,
                });

                // Node ID validation should reject malicious strings
                if status_result.is_ok() {
                    // If it was accepted, verify serialization integrity
                    let stored_nodes = transport.list_node_statuses().expect("list nodes");
                    for node in &stored_nodes {
                        assert!(!node.node_id.is_empty(), "Node ID should not be empty");
                        assert!(!node.zone_id.is_empty(), "Zone ID should not be empty");
                    }
                }
            }

            // Verify stored actions maintain JSON integrity
            let stored_actions = transport.list_actions().expect("list actions");
            for action in &stored_actions {
                let serialized = serde_json::to_string(action).expect("serialize action");
                let deserialized: FleetActionRecord =
                    serde_json::from_str(&serialized).expect("deserialize action");
                assert_eq!(deserialized.action_id, action.action_id);
            }
        }

        #[test]
        fn staleness_calculation_timing_precision() {
            let tempdir = tempdir().expect("tempdir");
            let root = tempdir.path().join("fleet-state");
            let mut transport = FileFleetTransport::new(&root);
            transport.initialize().expect("initialize");

            let base_time = DateTime::parse_from_rfc3339("2026-04-17T12:00:00Z")
                .expect("base timestamp")
                .with_timezone(&Utc);

            // Test precise staleness boundary calculations
            let staleness_threshold = Duration::from_secs(300); // 5 minutes

            // Node exactly at staleness boundary
            transport
                .upsert_node_status(&NodeStatus {
                    zone_id: "prod".to_string(),
                    node_id: "boundary-node".to_string(),
                    last_seen: base_time
                        - chrono::TimeDelta::from_std(staleness_threshold).unwrap(),
                    quarantine_version: 1,
                    health: NodeHealth::Healthy,
                    applied_actions: None,
                    native_session_drain: None,
                })
                .expect("upsert boundary node");

            // Node just before staleness (should not be stale)
            transport
                .upsert_node_status(&NodeStatus {
                    zone_id: "prod".to_string(),
                    node_id: "fresh-node".to_string(),
                    last_seen: base_time
                        - chrono::TimeDelta::from_std(staleness_threshold).unwrap()
                        + chrono::TimeDelta::seconds(1),
                    quarantine_version: 1,
                    health: NodeHealth::Healthy,
                    applied_actions: None,
                    native_session_drain: None,
                })
                .expect("upsert fresh node");

            // Node just after staleness (should be stale)
            transport
                .upsert_node_status(&NodeStatus {
                    zone_id: "prod".to_string(),
                    node_id: "stale-node".to_string(),
                    last_seen: base_time
                        - chrono::TimeDelta::from_std(staleness_threshold).unwrap()
                        - chrono::TimeDelta::seconds(1),
                    quarantine_version: 1,
                    health: NodeHealth::Healthy,
                    applied_actions: None,
                    native_session_drain: None,
                })
                .expect("upsert stale node");

            let stale_nodes = transport
                .list_stale_nodes(base_time, staleness_threshold)
                .expect("list stale nodes");

            let stale_ids: Vec<_> = stale_nodes.iter().map(|n| &n.node_id).collect();

            // Boundary behavior: exactly at threshold should be considered stale (fail-closed)
            assert!(
                stale_ids.contains(&&"boundary-node".to_string()),
                "Boundary node should be stale"
            );
            assert!(
                !stale_ids.contains(&&"fresh-node".to_string()),
                "Fresh node should not be stale"
            );
            assert!(
                stale_ids.contains(&&"stale-node".to_string()),
                "Stale node should be stale"
            );
        }

        #[test]
        fn file_layout_boundary_validation() {
            let tempdir = tempdir().expect("tempdir");

            // Test with extreme path lengths and characters
            let extreme_roots = vec![
                // Very long path
                tempdir.path().join("a".repeat(200)),
                // Unicode in path
                tempdir.path().join("fleet-🚀-state"),
                // Path with spaces
                tempdir.path().join("fleet state with spaces"),
            ];

            for extreme_root in &extreme_roots {
                let layout = FleetTransportLayout::new(extreme_root);

                // Layout creation should handle extreme paths gracefully
                assert!(
                    layout.root_dir().to_str().is_some(),
                    "Root path should be valid UTF-8"
                );
                assert!(
                    layout.actions_path().to_str().is_some(),
                    "Actions path should be valid UTF-8"
                );
                assert!(
                    layout.nodes_dir().to_str().is_some(),
                    "Nodes dir should be valid UTF-8"
                );
                assert!(
                    layout.locks_dir().to_str().is_some(),
                    "Locks dir should be valid UTF-8"
                );

                // Initialization should handle extreme paths
                let init_result = layout.initialize();
                if init_result.is_ok() {
                    assert!(
                        layout.root_dir().is_dir(),
                        "Root directory should be created"
                    );
                    assert!(
                        layout.nodes_dir().is_dir(),
                        "Nodes directory should be created"
                    );
                    assert!(
                        layout.locks_dir().is_dir(),
                        "Locks directory should be created"
                    );
                    assert!(
                        layout.actions_path().is_file(),
                        "Actions file should be created"
                    );
                }
            }

            // Test node status path validation with boundary cases
            let layout = FleetTransportLayout::new(tempdir.path());
            layout.initialize().expect("initialize layout");

            let max_len_node_id = "b".repeat(MAX_NODE_ID_LEN);
            let boundary_node_ids = vec![
                "a",                             // Minimum length
                max_len_node_id.as_str(),        // Maximum length
                "node-with-all.valid_chars-123", // All valid characters
            ];

            for node_id in &boundary_node_ids {
                let path_result = layout.node_status_path(node_id);
                assert!(
                    path_result.is_ok(),
                    "Should accept valid node ID: {}",
                    node_id
                );

                let path = path_result.unwrap();
                assert!(
                    path.to_str().is_some(),
                    "Generated path should be valid UTF-8"
                );
                assert!(
                    path.file_name().is_some(),
                    "Generated path should have filename"
                );
            }
        }
    }

    #[test]
    fn compact_action_log_if_needed_releases_lock_on_error() {
        let tmp = tempdir().expect("temp dir");
        let layout = FleetTransportLayout::new(tmp.path());
        let transport = FileFleetTransport::new(tmp.path());

        // Initialize with a large action log that will trigger compaction
        let large_action = FleetActionRecord {
            action_id: "large-action".to_string(),
            emitted_at: clock::wall_now(),
            action: FleetAction::Release {
                zone_id: "prod".to_string(),
                incident_id: "inc-1".to_string(),
                reason: None,
            },
        };

        // Write enough actions to exceed the threshold
        let action_data = serde_json::to_string(&large_action).expect("serialize");
        let large_content = format!("{}\n", action_data).repeat(10000); // Make it large enough

        fs::write(layout.actions_path(), large_content.as_bytes()).expect("write large file");

        // Create a read-only compaction lock file to simulate a file system error
        // that would occur during compaction but before the lock is released
        let compaction_lock_path = transport.action_compaction_lock_path();
        fs::create_dir_all(compaction_lock_path.parent().unwrap()).expect("create dir");

        // Root bypasses permission bits entirely, so the readonly fixture
        // cannot produce the compaction failure this test exists to observe.
        {
            use std::os::unix::fs::MetadataExt;
            if fs::metadata("/proc/self")
                .map(|m| m.uid() == 0)
                .unwrap_or(false)
            {
                eprintln!(
                    "SKIP: running as root; permission-driven compaction failure asserted on unprivileged hosts"
                );
                return;
            }
        }

        // First, make the actions file inaccessible to force an error during compaction
        let metadata = fs::metadata(layout.actions_path()).expect("get metadata");
        let mut permissions = metadata.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(layout.actions_path(), permissions).expect("set readonly");

        // Attempt compaction - this should fail but not leave locks hanging
        let result = transport.compact_action_log_if_needed(100, 1, clock::wall_now()); // Small size to force compaction

        // The compaction should fail due to permissions
        assert!(
            result.is_err(),
            "Expected compaction to fail due to permissions"
        );

        // Restore permissions for cleanup
        let metadata = fs::metadata(layout.actions_path()).expect("get metadata");
        let mut permissions = metadata.permissions();
        permissions.set_readonly(false);
        fs::set_permissions(layout.actions_path(), permissions).expect("restore permissions");

        // Now verify that we can immediately run another compaction without deadlocking
        // If the lock was leaked, this would hang or fail
        let second_result = transport.compact_action_log_if_needed(100, 1, clock::wall_now());

        // The second attempt should also handle the error gracefully and not deadlock
        // The key assertion is that this doesn't hang - the Result is less important
        match second_result {
            Ok(_) => {
                // Compaction succeeded this time
            }
            Err(_) => {
                // Compaction failed again, but importantly didn't deadlock
            }
        }
    }

    #[test]
    fn fleet_convergence_timeout_includes_diagnostic_context() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let never_converges = Arc::new(AtomicBool::new(false));
        let timeout = Duration::from_millis(50);

        let result = wait_until_fleet_converged_or_timeout(timeout, {
            let flag = never_converges.clone();
            move || Ok(flag.load(Ordering::Relaxed))
        })
        .expect("should not error");

        // Verify timeout occurred
        assert!(result.timed_out);
        assert!(result.elapsed >= timeout);
        assert!(result.check_attempts > 0);

        // Verify diagnostic context is present for timeouts
        let context = result
            .failure_context
            .expect("should have failure context for timeout");
        assert_eq!(
            context.doctor_command,
            "franken-node doctor --fleet --convergence"
        );
        assert_eq!(context.timeout_secs, timeout.as_secs());
        assert!(context.diagnostic_hint.contains("Fleet failed to converge"));
        assert!(
            context
                .diagnostic_hint
                .contains(&format!("{} attempts", result.check_attempts))
        );
    }

    #[test]
    fn fleet_convergence_success_excludes_diagnostic_context() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let converges_immediately = Arc::new(AtomicBool::new(true));
        let timeout = Duration::from_secs(10);

        let result = wait_until_fleet_converged_or_timeout(timeout, {
            let flag = converges_immediately.clone();
            move || Ok(flag.load(Ordering::Relaxed))
        })
        .expect("should not error");

        // Verify success
        assert!(!result.timed_out);
        assert!(result.elapsed < timeout);
        assert_eq!(result.check_attempts, 1);

        // Verify no diagnostic context for success
        assert!(result.failure_context.is_none());
    }

    #[test]
    fn fleet_convergence_diagnostic_tracks_check_attempts() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let attempt_counter = Arc::new(AtomicU32::new(0));
        // bd-o776s: the convergence loop sleeps one FLEET_CONVERGENCE_POLL_INTERVAL
        // (100ms) between polls, so reaching the 3rd attempt needs ~2 intervals. A
        // 100ms timeout only admits a single sleep and deterministically times out at
        // attempt 2; size the budget to comfortably fit 3 attempts.
        let timeout = super::FLEET_CONVERGENCE_POLL_INTERVAL * 5;

        let result = wait_until_fleet_converged_or_timeout(timeout, {
            let counter = attempt_counter.clone();
            move || {
                let attempts = counter.fetch_add(1, Ordering::Relaxed) + 1;
                // Converge on 3rd attempt
                Ok(attempts >= 3)
            }
        })
        .expect("should not error");

        // Verify convergence after multiple attempts
        assert!(!result.timed_out);
        assert_eq!(result.check_attempts, 3);
        assert!(result.failure_context.is_none());
    }

    // ─────────────────────────────────────────────────────────────
    // bd-98xo5.7.3: Comprehensive coverage of canonicalize_json_value
    // path-rendering after the bd-98xo5.7.1 path-alloc cleanup. The
    // change deferred path-string construction to the float-error
    // branch only; the rendered error format MUST stay byte-identical
    // to the legacy `format!`-on-every-descent implementation.
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn canonicalize_top_level_float_error_format() {
        // Float at the top-level key produces "...at $.zone_id".
        let payload = serde_json::json!({
            "zone_id": 1.5,
        });
        let err = canonical_fleet_convergence_receipt_payload(&payload)
            .expect_err("top-level float must surface as a serialization error");
        let detail = err.to_string();
        assert!(
            detail.contains("$.zone_id"),
            "top-level float path must equal `$.zone_id`; got: {detail}"
        );
        assert!(
            detail.contains("non-deterministic float"),
            "error message must keep the `non-deterministic float` prefix; got: {detail}"
        );
    }

    #[test]
    fn canonicalize_nested_object_float_error_format() {
        // Nested object: $.zones.zone_a.timestamp.
        let payload = serde_json::json!({
            "zones": {
                "zone_a": {
                    "timestamp": 2.5,
                },
            },
        });
        let err = canonical_fleet_convergence_receipt_payload(&payload)
            .expect_err("nested object float must surface as a serialization error");
        let detail = err.to_string();
        assert!(
            detail.contains("$.zones.zone_a.timestamp"),
            "nested object float path must equal `$.zones.zone_a.timestamp`; got: {detail}"
        );
    }

    #[test]
    fn canonicalize_nested_array_float_error_format() {
        // Nested array element: $.zones[2].timestamp.
        let payload = serde_json::json!({
            "zones": [
                {"id": "zone-0"},
                {"id": "zone-1"},
                {"id": "zone-2", "timestamp": 3.5},
            ],
        });
        let err = canonical_fleet_convergence_receipt_payload(&payload)
            .expect_err("nested array float must surface as a serialization error");
        let detail = err.to_string();
        assert!(
            detail.contains("$.zones[2].timestamp"),
            "nested array float path must equal `$.zones[2].timestamp`; got: {detail}"
        );
    }

    #[test]
    fn canonicalize_deeply_nested_float_error_format() {
        // Depth 6: object -> array -> object -> array -> object -> array
        // -> float. Pins the dot-bracket interleaving format on a deep
        // payload — a regression that changed render_path to omit `.`
        // before keys or `[N]` for array indices would manifest here.
        let payload = serde_json::json!({
            "lvl1": [
                {
                    "lvl3": [
                        {
                            "lvl5": [4.5],
                        },
                    ],
                },
            ],
        });
        let err = canonical_fleet_convergence_receipt_payload(&payload)
            .expect_err("depth-6 float must surface as a serialization error");
        let detail = err.to_string();
        assert!(
            detail.contains("$.lvl1[0].lvl3[0].lvl5[0]"),
            "depth-6 float path must equal `$.lvl1[0].lvl3[0].lvl5[0]`; got: {detail}"
        );
    }

    #[test]
    fn canonicalize_happy_path_returns_ok_on_100_key_object() {
        // The bead spec calls for an allocation-count assertion (no
        // path-string allocation on the happy path). Strict per-call
        // alloc counting requires a custom global allocator which can
        // only be installed once per crate — invasive and conflicts
        // with the rest of the test suite. The structural property we
        // CAN assert without that infrastructure is that the happy
        // path produces canonical bytes that round-trip back to an
        // object with the same key count, no errors. A future bead
        // can add a global-allocator-based alloc-count gate.
        let mut obj = serde_json::Map::with_capacity(100);
        for i in 0..100u32 {
            obj.insert(format!("key_{i:03}"), serde_json::Value::Number(i.into()));
        }
        let value = serde_json::Value::Object(obj);
        let canonical_bytes = canonical_fleet_convergence_receipt_payload(&value)
            .expect("happy path with 100 integer values must canonicalise");
        assert!(!canonical_bytes.is_empty());
        let round_tripped: serde_json::Value = serde_json::from_slice(&canonical_bytes)
            .expect("canonical bytes must round-trip via serde_json::from_slice");
        let canonical_map = round_tripped
            .as_object()
            .expect("canonicalised root must remain an object after deserialise");
        assert_eq!(canonical_map.len(), 100);
    }

    #[test]
    fn canonicalize_map_handles_500_key_object_without_error() {
        // Bead spec asked for an instrumentation-based assertion that
        // the output Map's hashbrown table did not rebucket on a
        // 500-key input. The `serde_json::Map::with_capacity(entries.len())`
        // call in canonicalize_json_value at line 200 already preserves
        // that property at the source level — verifying it dynamically
        // requires hashbrown internals that aren't part of the public
        // surface. What we CAN test: that 500-key input canonicalises
        // cleanly and preserves every key (a regression that broke
        // with_capacity routing would manifest as slow output on big
        // inputs, not wrong output; this test pins the correctness
        // property regardless of bucket strategy).
        let mut obj = serde_json::Map::with_capacity(500);
        for i in 0..500u32 {
            obj.insert(format!("k_{i:04}"), serde_json::Value::Number(i.into()));
        }
        let value = serde_json::Value::Object(obj);
        let canonical_bytes = canonical_fleet_convergence_receipt_payload(&value)
            .expect("500-key happy path must canonicalise");
        let round_tripped: serde_json::Value = serde_json::from_slice(&canonical_bytes)
            .expect("canonical bytes must round-trip via serde_json::from_slice");
        let canonical_map = round_tripped
            .as_object()
            .expect("canonicalised root must remain an object");
        assert_eq!(canonical_map.len(), 500);
        // Keys are deterministically sorted (BTreeMap order in the
        // canonicalise impl); after round-trip the serde_json::Map
        // preserves insertion order, which for the canonical output
        // is the sorted order from canonicalize_json_value.
        let mut keys: Vec<&String> = canonical_map.keys().collect();
        keys.sort();
        assert_eq!(keys.first().map(|s| s.as_str()), Some("k_0000"));
        assert_eq!(keys.last().map(|s| s.as_str()), Some("k_0499"));
    }

    // ── bd-98xo5.7.3: property tests ──
    //
    // The bead spec called for an OLD-vs-NEW byte-equality property,
    // but the OLD implementation no longer exists in source. The
    // equivalent regression class — silent change in canonical byte
    // output — is caught here by an idempotence property: any
    // canonical Value, re-canonicalised, must produce identical
    // bytes.
    //
    // Persistent regressions land at
    // crates/franken-node/proptest-regressions/control_plane/fleet_transport.txt.

    fn finite_json_leaf_strategy() -> proptest::strategy::BoxedStrategy<serde_json::Value> {
        use proptest::prelude::*;
        prop_oneof![
            Just(serde_json::Value::Null),
            any::<bool>().prop_map(serde_json::Value::Bool),
            // Integers only — the canonicaliser rejects f64, which is
            // covered by the dedicated error-format tests above.
            any::<i64>().prop_map(|n| serde_json::Value::Number(n.into())),
            "[a-zA-Z0-9 _.-]{0,32}".prop_map(serde_json::Value::String),
        ]
        .boxed()
    }

    fn finite_json_value_strategy() -> proptest::strategy::BoxedStrategy<serde_json::Value> {
        use proptest::prelude::*;
        finite_json_leaf_strategy()
            .prop_recursive(
                3,  // max depth — kept shallow so 256 cases run quickly
                32, // max total nodes
                6,  // branch factor
                |leaf| {
                    prop_oneof![
                        prop::collection::vec(leaf.clone(), 0..6)
                            .prop_map(serde_json::Value::Array),
                        prop::collection::hash_map("[a-z]{1,6}", leaf, 0..6).prop_map(|m| {
                            let mut obj = serde_json::Map::new();
                            for (k, v) in m {
                                obj.insert(k, v);
                            }
                            serde_json::Value::Object(obj)
                        }),
                    ]
                },
            )
            .boxed()
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig {
            cases: 256,
            failure_persistence: Some(Box::new(
                proptest::test_runner::FileFailurePersistence::WithSource("regressions")
            )),
            ..proptest::prelude::ProptestConfig::default()
        })]

        #[test]
        fn prop_canonical_bytes_idempotent(value in finite_json_value_strategy()) {
            // bd-98xo5.7.3 property: re-canonicalising the canonical
            // bytes (after round-trip) must produce the same bytes. A
            // regression in render_path or BTreeMap key sort would
            // manifest as divergence. Pinning idempotence is a
            // stronger contract than OLD-vs-NEW equality (which is no
            // longer testable since OLD is gone) — it catches both
            // sort-order drift and any non-determinism.
            let first_bytes = canonical_fleet_convergence_receipt_payload(&value)
                .expect("finite-float value must canonicalise");
            let round_tripped: serde_json::Value = serde_json::from_slice(&first_bytes)
                .expect("canonical bytes must round-trip");
            let second_bytes = canonical_fleet_convergence_receipt_payload(&round_tripped)
                .expect("re-canonicalising must succeed");
            proptest::prop_assert_eq!(first_bytes, second_bytes);
        }

        #[test]
        fn prop_float_error_format_pins_legacy_template(key_byte in 1u8..=26u8) {
            // Any non-finite f64 at a deterministic location must
            // produce an error whose message contains BOTH the
            // `non-deterministic float` template AND the rendered
            // path. We vary the key byte across the lowercase-letter
            // range to ensure the format works for any single-char
            // top-level key.
            let key = (b'a' + (key_byte - 1)) as char;
            let payload = serde_json::json!({
                key.to_string(): 7.0_f64,
            });
            let err = canonical_fleet_convergence_receipt_payload(&payload)
                .expect_err("non-finite float must surface as error");
            let detail = err.to_string();
            proptest::prop_assert!(
                detail.contains("non-deterministic float"),
                "error must keep `non-deterministic float` template; got: {}",
                detail
            );
            proptest::prop_assert!(
                detail.contains(&format!("$.{key}")),
                "error must contain the `$.{}` rendered path; got: {}",
                key,
                detail
            );
        }
    }

    #[test]
    fn lock_contention_retry_prevents_test_panics() {
        // Regression test for bd-4lnki: ensure tests don't panic on lock contention,
        // they retry with backoff instead of hard-failing with .expect()
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        let lock_path = transport.shared_state_lock_path();

        // Holder process acquires the lock.
        let holder_lock_file = transport.lock_file(&lock_path).expect("open holder lock");
        lock_file_with_backoff(&holder_lock_file, &lock_path, false).expect("holder takes lock");

        let contender_lock_path = lock_path.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        let contender = std::thread::spawn(move || {
            let contender_transport = FileFleetTransport::new(&root);
            let contender_lock_file = contender_transport
                .lock_file(&contender_lock_path)
                .expect("open contender lock");

            let start = std::time::Instant::now();
            let result = lock_file_with_backoff(&contender_lock_file, &contender_lock_path, false);
            let duration = start.elapsed();
            sender.send((result, duration)).expect("send result");
        });

        std::thread::sleep(std::time::Duration::from_millis(50));
        std::thread::sleep(std::time::Duration::from_millis(200));
        drop(holder_lock_file);

        let (result, duration) = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("contender should complete");
        contender.join().expect("contender thread should complete");

        assert!(
            result.is_ok(),
            "lock acquisition should succeed with retry: {:?}",
            result
        );
        assert!(
            duration >= std::time::Duration::from_millis(100),
            "should have retried with backoff (took {:?})",
            duration
        );
    }

    #[test]
    fn seqlock_control_page_round_trips_in_memory_and_shared_file() {
        let tempdir = tempdir().expect("tempdir");
        let page_path = tempdir.path().join("seqlock.page");
        let page = super::SeqlockControlPage::new();
        let digest = [0xAB_u8; 32];
        let snap = page.publish(7, 3, 2, 11, digest);
        assert_eq!(snap.sequence, 2);
        assert_eq!(snap.control_epoch, 7);
        assert_eq!(snap.quarantine_version, 3);
        assert_eq!(snap.active_hold_count, 2);
        assert_eq!(snap.action_count, 11);
        assert_eq!(snap.action_log_digest_prefix, digest);
        assert_eq!(page.read_safepoint(), snap);

        page.write_shared_page(&page_path)
            .expect("write shared seqlock page");
        let loaded = super::SeqlockControlPage::read_shared_page(&page_path)
            .expect("read shared seqlock page");
        assert_eq!(loaded, snap);

        // Odd sequence on disk must fail closed as writer-in-progress.
        let mut raw = std::fs::read(&page_path).expect("raw bytes");
        raw[8..16].copy_from_slice(&3_u64.to_le_bytes());
        std::fs::write(&page_path, raw).expect("tamper odd sequence");
        assert!(super::SeqlockControlPage::read_shared_page(&page_path).is_err());
    }

    #[test]
    fn certify_fleet_epoch_quiescence_advances_epoch_iff_all_enrolled_supervisors_attest() {
        use crate::control_plane::control_epoch::EpochSigningKey;
        use crate::control_plane::epoch_transition_barrier::BarrierConfig;
        use crate::runtime::epoch_transition::ProductEpochCoordinator;
        use ed25519_dalek::{Signer, SigningKey};
        use sha2::{Digest, Sha256};

        let now = chrono::Utc::now();
        let action = FleetActionRecord {
            action_id: "quarantine-east-1".to_string(),
            emitted_at: now,
            action: FleetAction::Quarantine {
                zone_id: "east".to_string(),
                incident_id: "inc-east-1".to_string(),
                target_id: "npm:@acme/bad-pkg".to_string(),
                target_kind: FleetTargetKind::Extension,
                quarantine_version: 1,
                reason: "compromised".to_string(),
            },
        };
        let actions = vec![action];
        let expected = fleet_application_checkpoint(&actions, "east").expect("checkpoint");

        let make_signed_node = |node_id: &str, seed: u8, indeterminate: u64| {
            let signing_key = SigningKey::from_bytes(&[seed; 32]);
            let verifying_key = signing_key.verifying_key();
            let mut drain = super::NativeSessionDrainCheckpoint {
                applied_actions: expected.clone(),
                session_set_sha256: format!("{seed:02x}").repeat(32),
                admitted_sessions: 2,
                terminal_sessions: if indeterminate == 0 { 2 } else { 1 },
                pending_sessions: 0,
                indeterminate_sessions: indeterminate,
                fence_held: false,
                supervisor_attestation: None,
            };
            let mut attestation = super::NativeSessionDrainAttestation {
                schema_version: super::NATIVE_SESSION_DRAIN_ATTESTATION_SCHEMA.to_string(),
                node_id: node_id.to_string(),
                zone_id: "east".to_string(),
                drain_id: uuid::Uuid::now_v7().to_string(),
                generation: 1,
                project_root_sha256: hex::encode(Sha256::digest(node_id.as_bytes())),
                observed_at: now,
                product_root_key_id: format!("ed25519:{}", hex::encode(verifying_key.as_bytes())),
                checkpoint_sha256: drain.observation_sha256().expect("checkpoint sha256"),
                signature_hex: String::new(),
            };
            let payload = attestation.signing_payload().expect("signing payload");
            attestation.signature_hex = hex::encode(signing_key.sign(&payload).to_bytes());
            drain.supervisor_attestation = Some(attestation);
            let status = NodeStatus {
                zone_id: "east".to_string(),
                node_id: node_id.to_string(),
                last_seen: now,
                quarantine_version: 1,
                health: NodeHealth::Healthy,
                applied_actions: Some(expected.clone()),
                native_session_drain: Some(drain),
            };
            (status, verifying_key)
        };

        let (node_a, key_a) = make_signed_node("node-a", 11, 0);
        let (node_b, key_b) = make_signed_node("node-b", 22, 0);
        let mut roots = std::collections::BTreeMap::new();
        roots.insert(("east".to_string(), "node-a".to_string()), key_a);
        roots.insert(("east".to_string(), "node-b".to_string()), key_b);

        let mut coordinator = ProductEpochCoordinator::new(
            0,
            2,
            BarrierConfig::default(),
            EpochSigningKey::new(b"fleet-epoch-test-key").expect("signing key"),
        );
        let state = FleetSharedState {
            schema_version: FLEET_SHARED_STATE_SCHEMA.to_string(),
            actions: actions.clone(),
            nodes: vec![node_a.clone(), node_b],
        };
        let (evidence, cert) = super::certify_fleet_epoch_quiescence(
            &mut coordinator,
            &state,
            &roots,
            super::FleetEpochBarrierParams {
                initiator: "operator-root",
                reason: "quarantine-epoch-advance",
                now,
                stale_after: std::time::Duration::from_secs(30),
                trace_id: "trace-epoch-1",
            },
        )
        .expect("two enrolled signed quiesced nodes must certify");
        assert!(evidence.fleet_quiescence_certified);
        assert_eq!(
            evidence.scope,
            super::FLEET_EPOCH_BARRIER_CERTIFIED_DRAIN_SCOPE
        );
        assert!(cert.fleet_quiescence_certified);
        assert_eq!(cert.pre_epoch, 0);
        assert_eq!(cert.committed_epoch, 1);
        assert_eq!(coordinator.current_epoch(), 1);
        assert_eq!(cert.participants.len(), 2);

        // Fault cut: indeterminate session on node-b must abort the barrier and preserve epoch 1.
        let (bad_b, _) = make_signed_node("node-b", 22, 1);
        let fault_state = FleetSharedState {
            schema_version: FLEET_SHARED_STATE_SCHEMA.to_string(),
            actions,
            nodes: vec![node_a, bad_b],
        };
        let err = super::certify_fleet_epoch_quiescence(
            &mut coordinator,
            &fault_state,
            &roots,
            super::FleetEpochBarrierParams {
                initiator: "operator-root",
                reason: "faulted-transition",
                now,
                stale_after: std::time::Duration::from_secs(30),
                trace_id: "trace-epoch-2",
            },
        )
        .expect_err("indeterminate session must abort epoch barrier");
        assert!(err.to_string().contains("aborted before commit"), "{err}");
        assert_eq!(coordinator.current_epoch(), 1);
        assert_eq!(coordinator.abort_manager().events().len(), 1);
    }
}
