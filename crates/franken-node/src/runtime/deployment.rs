//! Authenticated application deployments with crash-loop recovery to a
//! known-good release (bd-reality-20260923-26n9r.22, plan 10.13 item 10).
//!
//! A *deployment* is a named application slot owned by an operator project
//! (the deployment root). Each *release* is an immutable application project
//! directory admitted through its publisher-signed source-graph approval; the
//! release record binds that approval, the release's own `franken_node.toml`,
//! the engine compatibility it was admitted under, and its location. The
//! *activation pointer* names the release that runs. It is the only thing a
//! recovery switches: release directories, failed releases, crash records and
//! audit history are never deleted or rewritten.
//!
//! Every record is signed by the deployment authority (the deployment root's
//! receipt signing key), and activations form a hash chain, so an edited
//! pointer, a swapped release record or a forged health event fails
//! verification and leaves the deployment contained.
//!
//! Recovery is driven by the native supervisor's validated crash-loop
//! observation (`safe_mode::record_native_crash`). Each release is its own
//! run scope, so the crash-loop safe mode the supervisor enters stays on the
//! failed release; a known-good sibling can run without bypassing it, while
//! an operator safe mode on the deployment root still blocks every release.
//! A known-good release is one that previously ran healthy under this
//! deployment, never crash-looped, and still verifies: its record signature,
//! directory, config bytes, publisher approval, on-disk source graph, current
//! trust admission (no publisher or artifact revocation) and engine
//! compatibility (checked by the caller-supplied verifier).

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::supply_chain::registry_artifact::PublisherSourceGraphApproval;

/// Deployment state lives under the deployment root's state directory.
pub const DEPLOYMENTS_RELATIVE_DIR: &str = ".franken-node/state/deployments";
pub const RELEASE_SCHEMA: &str = "franken-node/deployment-release/v1";
pub const POLICY_SCHEMA: &str = "franken-node/deployment-policy/v1";
pub const ACTIVATION_SCHEMA: &str = "franken-node/deployment-activation/v1";
pub const HEALTH_SCHEMA: &str = "franken-node/deployment-release-health/v1";
pub const RECOVERY_SCHEMA: &str = "franken-node/deployment-recovery/v1";

/// Domain separator for every deployment record signature.
const SIGNATURE_DOMAIN: &[u8] = b"franken-node:deployment-record:v1\0";
/// Releases retained per deployment.
pub const MAX_RELEASES: usize = 256;
/// Activations retained per deployment (the chain is verified end to end).
pub const MAX_ACTIVATIONS: u64 = 4_096;
/// Recoveries retained per deployment.
pub const MAX_RECOVERIES: u64 = 4_096;
/// Health events retained per release; the oldest healthy runs are evicted
/// first, crash-loop marks are never evicted.
pub const MAX_HEALTH_EVENTS: usize = 512;
const MAX_RECORD_BYTES: u64 = 1 << 20;
const MAX_NAME_BYTES: usize = 64;
const MAX_REASON_BYTES: usize = 512;

/// Signing identity of a deployment root.
pub struct DeploymentAuthority {
    signing_key: SigningKey,
}

impl DeploymentAuthority {
    #[must_use]
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key().as_bytes())
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    fn seal<T: Serialize>(&self, payload: T) -> Result<SignedRecord<T>> {
        let message = signing_message(&payload)?;
        let signature = self.signing_key.sign(&message);
        Ok(SignedRecord {
            payload,
            signer_public_key_hex: self.public_key_hex(),
            signature_hex: hex::encode(signature.to_bytes()),
        })
    }

    fn open<T: Serialize>(&self, record: &SignedRecord<T>, label: &str) -> Result<()> {
        anyhow::ensure!(
            record.signer_public_key_hex == self.public_key_hex(),
            "{label} was not signed by this deployment authority"
        );
        let signature_bytes: [u8; 64] = hex::decode(&record.signature_hex)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .with_context(|| format!("{label} carries a malformed signature"))?;
        let message = signing_message(&record.payload)?;
        self.verifying_key()
            .verify(&message, &Signature::from_bytes(&signature_bytes))
            .map_err(|_| anyhow::anyhow!("{label} failed signature verification"))
    }
}

fn signing_message<T: Serialize>(payload: &T) -> Result<Vec<u8>> {
    let mut message = SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(&serde_json::to_vec(payload)?);
    Ok(message)
}

fn record_digest<T: Serialize>(record: &SignedRecord<T>) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(signing_message(&record.payload)?);
    hasher.update(record.signature_hex.as_bytes());
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedRecord<T> {
    payload: T,
    signer_public_key_hex: String,
    signature_hex: String,
}

/// One admitted, immutable application release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRecord {
    pub schema_version: String,
    pub deployment: String,
    pub release_id: String,
    /// Absolute canonical release project directory.
    pub release_dir: PathBuf,
    /// Release-relative entrypoint the publisher approved.
    pub entrypoint: String,
    /// SHA-256 of the release's `franken_node.toml` at admission.
    pub config_sha256: String,
    /// Absolute path of the publisher-signed source-capsule manifest.
    pub registry_manifest: PathBuf,
    /// Absolute path of the independently retained publisher public key.
    pub publisher_public_key_path: PathBuf,
    /// The publisher-signed source-graph approval. Before every activation
    /// and run it is loaded again from `registry_manifest` with the key at
    /// `publisher_public_key_path` and must be identical.
    pub approval: PublisherSourceGraphApproval,
    /// Product/engine build the release was admitted under.
    pub engine_compatibility: String,
    pub installed_at_epoch_secs: u64,
}

/// What the supervisor does when a release crash-loops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrashLoopAction {
    /// Stay contained in the failed release's safe mode (default).
    Contain,
    /// Switch the activation pointer to the newest verified known-good release.
    Rollback,
}

/// Whether the supervisor may start the selected release itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartPolicy {
    /// The operator starts the next run (default).
    Operator,
    /// The supervisor starts the selected release once, immediately.
    Automatic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentPolicy {
    pub schema_version: String,
    pub deployment: String,
    pub on_crash_loop: CrashLoopAction,
    pub restart: RestartPolicy,
    pub operator_id: String,
    pub set_at_epoch_secs: u64,
}

impl DeploymentPolicy {
    /// The policy in force before an operator sets one: contain, never restart.
    #[must_use]
    pub fn contained_default(deployment: &str) -> Self {
        Self {
            schema_version: POLICY_SCHEMA.to_string(),
            deployment: deployment.to_string(),
            on_crash_loop: CrashLoopAction::Contain,
            restart: RestartPolicy::Operator,
            operator_id: String::new(),
            set_at_epoch_secs: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationReason {
    Operator,
    CrashLoopRollback,
}

/// One link of the activation chain; the latest link is the pointer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationRecord {
    pub schema_version: String,
    pub deployment: String,
    pub sequence: u64,
    pub release_id: String,
    pub reason: ActivationReason,
    pub operator_id: Option<String>,
    /// The recovery that committed this activation, if any.
    pub recovery_sequence: Option<u64>,
    pub previous_activation_digest: Option<String>,
    pub activated_at_epoch_secs: u64,
}

/// The supervisor's validated crash-loop observation for the failed release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrashLoopEvidence {
    pub session_nonce: String,
    pub entrypoint: String,
    pub observed_at_epoch_secs: u64,
    pub crashes_in_window: u32,
    pub threshold: u32,
    pub window_secs: u64,
    pub safe_mode_state_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HealthEvent {
    /// A run of this release completed with exit 0 under its signed receipt.
    HealthyRun {
        receipt_id: String,
        observed_at_epoch_secs: u64,
    },
    /// The native supervisor saw this release crash-loop.
    CrashLoop { evidence: CrashLoopEvidence },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseHealth {
    pub schema_version: String,
    pub deployment: String,
    pub release_id: String,
    pub events: Vec<HealthEvent>,
}

impl ReleaseHealth {
    #[must_use]
    pub fn healthy_runs(&self) -> usize {
        self.events
            .iter()
            .filter(|event| matches!(event, HealthEvent::HealthyRun { .. }))
            .count()
    }

    #[must_use]
    pub fn crash_looped(&self) -> bool {
        self.events
            .iter()
            .any(|event| matches!(event, HealthEvent::CrashLoop { .. }))
    }

    #[must_use]
    pub fn last_healthy_at(&self) -> Option<u64> {
        self.events
            .iter()
            .filter_map(|event| match event {
                HealthEvent::HealthyRun {
                    observed_at_epoch_secs,
                    ..
                } => Some(*observed_at_epoch_secs),
                HealthEvent::CrashLoop { .. } => None,
            })
            .max()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateRefusal {
    pub release_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryOutcome {
    /// Policy is `contain`: the failed release stays in its safe mode.
    Contained,
    /// Policy is `rollback` but no candidate verified; nothing was switched.
    ContainedNoKnownGood,
    /// The activation pointer now names the selected known-good release.
    RolledBack,
}

/// Signed, immutable account of one crash-loop recovery decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRecord {
    pub schema_version: String,
    pub deployment: String,
    pub sequence: u64,
    pub failed_release_id: String,
    pub crash: CrashLoopEvidence,
    pub on_crash_loop: CrashLoopAction,
    pub restart: RestartPolicy,
    pub outcome: RecoveryOutcome,
    pub selected_release_id: Option<String>,
    pub activation_sequence: Option<u64>,
    pub candidate_refusals: Vec<CandidateRefusal>,
    pub recorded_at_epoch_secs: u64,
}

/// Result of the known-good search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownGoodSelection {
    pub selected: Option<ReleaseRecord>,
    pub refusals: Vec<CandidateRefusal>,
}

/// Validate a deployment or release identifier.
pub fn validate_identifier(kind: &str, value: &str) -> Result<()> {
    anyhow::ensure!(
        !value.is_empty()
            && value.len() <= MAX_NAME_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            && !value.starts_with('.'),
        "{kind} `{value}` must be 1-{MAX_NAME_BYTES} ASCII letters, digits, '-', '_' or '.', not starting with '.'"
    );
    Ok(())
}

fn validate_operator_id(operator_id: &str) -> Result<()> {
    anyhow::ensure!(
        !operator_id.trim().is_empty() && operator_id.len() <= MAX_REASON_BYTES,
        "operator id must be non-empty and at most {MAX_REASON_BYTES} bytes"
    );
    Ok(())
}

/// Exclusive advisory lock over one deployment's state.
pub struct DeploymentLock {
    _file: File,
}

/// Filesystem store for one deployment.
pub struct DeploymentStore {
    name: String,
    root: PathBuf,
}

impl DeploymentStore {
    /// Open (without creating) the store of `name` under `deployment_root`.
    pub fn open(deployment_root: &Path, name: &str) -> Result<Self> {
        validate_identifier("deployment name", name)?;
        Ok(Self {
            name: name.to_string(),
            root: deployment_root.join(DEPLOYMENTS_RELATIVE_DIR).join(name),
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Serialize every read-modify-write of this deployment.
    pub fn lock(&self) -> Result<DeploymentLock> {
        use fs2::FileExt as _;
        fs::create_dir_all(&self.root)
            .with_context(|| format!("create deployment state {}", self.root.display()))?;
        let path = self.root.join("deployment.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("open deployment lock {}", path.display()))?;
        file.lock_exclusive()
            .with_context(|| format!("lock deployment {}", self.name))?;
        Ok(DeploymentLock { _file: file })
    }

    fn release_path(&self, release_id: &str) -> PathBuf {
        self.root
            .join("releases")
            .join(format!("{release_id}.json"))
    }

    fn health_path(&self, release_id: &str) -> PathBuf {
        self.root.join("health").join(format!("{release_id}.json"))
    }

    fn activation_path(&self, sequence: u64) -> PathBuf {
        self.root
            .join("activations")
            .join(format!("{sequence:010}.json"))
    }

    fn recovery_path(&self, sequence: u64) -> PathBuf {
        self.root
            .join("recoveries")
            .join(format!("{sequence:010}.json"))
    }

    fn pointer_path(&self) -> PathBuf {
        self.root.join("active.json")
    }

    fn policy_path(&self) -> PathBuf {
        self.root.join("policy.json")
    }

    /// Record a newly admitted release. Re-installing identical content is
    /// idempotent; a different release under an existing id is refused.
    pub fn install_release(
        &self,
        _lock: &DeploymentLock,
        authority: &DeploymentAuthority,
        release: ReleaseRecord,
    ) -> Result<bool> {
        validate_identifier("release id", &release.release_id)?;
        anyhow::ensure!(
            release.schema_version == RELEASE_SCHEMA && release.deployment == self.name,
            "release record does not belong to deployment `{}`",
            self.name
        );
        let path = self.release_path(&release.release_id);
        if path.exists() {
            let existing = self.release(authority, &release.release_id)?;
            anyhow::ensure!(
                existing == release,
                "release `{}` already exists with different content; choose a new --release-id",
                release.release_id
            );
            return Ok(false);
        }
        anyhow::ensure!(
            self.release_ids()?.len() < MAX_RELEASES,
            "deployment `{}` already retains {MAX_RELEASES} releases",
            self.name
        );
        write_new(&path, &authority.seal(release)?)?;
        Ok(true)
    }

    /// Load and verify one release record.
    pub fn release(
        &self,
        authority: &DeploymentAuthority,
        release_id: &str,
    ) -> Result<ReleaseRecord> {
        validate_identifier("release id", release_id)?;
        let record: SignedRecord<ReleaseRecord> = read_json(&self.release_path(release_id))
            .with_context(|| format!("release `{release_id}` of deployment `{}`", self.name))?;
        authority.open(&record, "release record")?;
        let release = record.payload;
        anyhow::ensure!(
            release.schema_version == RELEASE_SCHEMA
                && release.deployment == self.name
                && release.release_id == release_id,
            "release record `{release_id}` does not belong to deployment `{}`",
            self.name
        );
        Ok(release)
    }

    /// Release ids present on disk (unverified; use `release` to read one).
    pub fn release_ids(&self) -> Result<Vec<String>> {
        let directory = self.root.join("releases");
        let mut ids = Vec::new();
        if !directory.exists() {
            return Ok(ids);
        }
        for entry in fs::read_dir(&directory)
            .with_context(|| format!("list releases in {}", directory.display()))?
        {
            let name = entry?.file_name();
            if let Some(id) = name.to_str().and_then(|name| name.strip_suffix(".json"))
                && validate_identifier("release id", id).is_ok()
            {
                ids.push(id.to_string());
            }
        }
        ids.sort();
        Ok(ids)
    }

    pub fn set_policy(
        &self,
        _lock: &DeploymentLock,
        authority: &DeploymentAuthority,
        policy: DeploymentPolicy,
    ) -> Result<()> {
        anyhow::ensure!(
            policy.schema_version == POLICY_SCHEMA && policy.deployment == self.name,
            "policy does not belong to deployment `{}`",
            self.name
        );
        validate_operator_id(&policy.operator_id)?;
        write_replace(&self.policy_path(), &authority.seal(policy)?)
    }

    /// The signed policy, or the contained default when none was set.
    pub fn policy(&self, authority: &DeploymentAuthority) -> Result<DeploymentPolicy> {
        let path = self.policy_path();
        if !path.exists() {
            return Ok(DeploymentPolicy::contained_default(&self.name));
        }
        let record: SignedRecord<DeploymentPolicy> = read_json(&path)?;
        authority.open(&record, "deployment policy")?;
        anyhow::ensure!(
            record.payload.schema_version == POLICY_SCHEMA
                && record.payload.deployment == self.name,
            "deployment policy does not belong to deployment `{}`",
            self.name
        );
        Ok(record.payload)
    }

    /// Verified activation chain, oldest first. The pointer must equal the
    /// newest link; any gap, reordering, foreign link or edit is refused.
    pub fn activations(&self, authority: &DeploymentAuthority) -> Result<Vec<ActivationRecord>> {
        let mut chain: Vec<ActivationRecord> = Vec::new();
        let mut previous_digest: Option<String> = None;
        let mut sequence = 1_u64;
        while self.activation_path(sequence).exists() {
            anyhow::ensure!(
                sequence <= MAX_ACTIVATIONS,
                "deployment `{}` exceeds {MAX_ACTIVATIONS} activations",
                self.name
            );
            let record: SignedRecord<ActivationRecord> =
                read_json(&self.activation_path(sequence))?;
            authority.open(&record, "activation record")?;
            let activation = &record.payload;
            anyhow::ensure!(
                activation.schema_version == ACTIVATION_SCHEMA
                    && activation.deployment == self.name
                    && activation.sequence == sequence
                    && activation.previous_activation_digest == previous_digest,
                "activation chain of deployment `{}` is broken at sequence {sequence}",
                self.name
            );
            previous_digest = Some(record_digest(&record)?);
            chain.push(record.payload);
            sequence += 1;
        }
        let pointer = self.pointer_path();
        match (chain.last(), pointer.exists()) {
            (None, false) => {}
            (Some(latest), true) => {
                let record: SignedRecord<ActivationRecord> = read_json(&pointer)?;
                authority.open(&record, "activation pointer")?;
                anyhow::ensure!(
                    &record.payload == latest,
                    "activation pointer of deployment `{}` does not match its newest activation",
                    self.name
                );
            }
            (None, true) => anyhow::bail!(
                "activation pointer of deployment `{}` has no activation history",
                self.name
            ),
            (Some(_), false) => anyhow::bail!(
                "activation pointer of deployment `{}` is missing",
                self.name
            ),
        }
        Ok(chain)
    }

    /// The release the pointer names, if any.
    pub fn active(&self, authority: &DeploymentAuthority) -> Result<Option<ActivationRecord>> {
        Ok(self.activations(authority)?.pop())
    }

    /// Append an activation and move the pointer to it.
    #[allow(clippy::too_many_arguments)]
    pub fn activate(
        &self,
        _lock: &DeploymentLock,
        authority: &DeploymentAuthority,
        release_id: &str,
        reason: ActivationReason,
        operator_id: Option<&str>,
        recovery_sequence: Option<u64>,
        now_secs: u64,
    ) -> Result<ActivationRecord> {
        self.release(authority, release_id)?;
        if let Some(operator_id) = operator_id {
            validate_operator_id(operator_id)?;
        }
        let chain = self.activations(authority)?;
        let sequence = chain.last().map_or(1, |latest| latest.sequence + 1);
        anyhow::ensure!(
            sequence <= MAX_ACTIVATIONS,
            "deployment `{}` exceeds {MAX_ACTIVATIONS} activations",
            self.name
        );
        let previous_activation_digest = if sequence == 1 {
            None
        } else {
            let previous: SignedRecord<ActivationRecord> =
                read_json(&self.activation_path(sequence - 1))?;
            Some(record_digest(&previous)?)
        };
        let activation = ActivationRecord {
            schema_version: ACTIVATION_SCHEMA.to_string(),
            deployment: self.name.clone(),
            sequence,
            release_id: release_id.to_string(),
            reason,
            operator_id: operator_id.map(ToString::to_string),
            recovery_sequence,
            previous_activation_digest,
            activated_at_epoch_secs: now_secs,
        };
        let sealed = authority.seal(activation.clone())?;
        // History first: a crash between the two writes leaves the pointer on
        // the previous link, which `activations` reports as a mismatch rather
        // than silently running either release.
        write_new(&self.activation_path(sequence), &sealed)?;
        write_replace(&self.pointer_path(), &sealed)?;
        Ok(activation)
    }

    /// Verified health of one release (empty when nothing was recorded).
    pub fn health(
        &self,
        authority: &DeploymentAuthority,
        release_id: &str,
    ) -> Result<ReleaseHealth> {
        validate_identifier("release id", release_id)?;
        let path = self.health_path(release_id);
        if !path.exists() {
            return Ok(ReleaseHealth {
                schema_version: HEALTH_SCHEMA.to_string(),
                deployment: self.name.clone(),
                release_id: release_id.to_string(),
                events: Vec::new(),
            });
        }
        let record: SignedRecord<ReleaseHealth> = read_json(&path)?;
        authority.open(&record, "release health")?;
        anyhow::ensure!(
            record.payload.schema_version == HEALTH_SCHEMA
                && record.payload.deployment == self.name
                && record.payload.release_id == release_id,
            "release health `{release_id}` does not belong to deployment `{}`",
            self.name
        );
        Ok(record.payload)
    }

    pub fn record_health(
        &self,
        _lock: &DeploymentLock,
        authority: &DeploymentAuthority,
        release_id: &str,
        event: HealthEvent,
    ) -> Result<ReleaseHealth> {
        self.release(authority, release_id)?;
        let mut health = self.health(authority, release_id)?;
        if let HealthEvent::HealthyRun { receipt_id, .. } = &event {
            anyhow::ensure!(
                !receipt_id.is_empty() && receipt_id.len() <= MAX_REASON_BYTES,
                "healthy run receipt id is invalid"
            );
            if health.events.iter().any(|existing| {
                matches!(existing, HealthEvent::HealthyRun { receipt_id: seen, .. } if seen == receipt_id)
            }) {
                return Ok(health);
            }
        }
        health.events.push(event);
        while health.events.len() > MAX_HEALTH_EVENTS {
            let Some(oldest_healthy) = health
                .events
                .iter()
                .position(|event| matches!(event, HealthEvent::HealthyRun { .. }))
            else {
                anyhow::bail!(
                    "release `{release_id}` retains {MAX_HEALTH_EVENTS} crash-loop marks; none may be evicted"
                );
            };
            health.events.remove(oldest_healthy);
        }
        write_replace(
            &self.health_path(release_id),
            &authority.seal(health.clone())?,
        )?;
        Ok(health)
    }

    /// Verified recoveries, oldest first.
    pub fn recoveries(&self, authority: &DeploymentAuthority) -> Result<Vec<RecoveryRecord>> {
        let mut recoveries = Vec::new();
        let mut sequence = 1_u64;
        while self.recovery_path(sequence).exists() {
            anyhow::ensure!(
                sequence <= MAX_RECOVERIES,
                "deployment `{}` exceeds {MAX_RECOVERIES} recoveries",
                self.name
            );
            let record: SignedRecord<RecoveryRecord> = read_json(&self.recovery_path(sequence))?;
            authority.open(&record, "recovery record")?;
            anyhow::ensure!(
                record.payload.schema_version == RECOVERY_SCHEMA
                    && record.payload.deployment == self.name
                    && record.payload.sequence == sequence,
                "recovery history of deployment `{}` is broken at sequence {sequence}",
                self.name
            );
            recoveries.push(record.payload);
            sequence += 1;
        }
        Ok(recoveries)
    }

    /// Search the activation history, newest first, for a known-good release:
    /// previously activated, ran healthy at least once, never crash-looped,
    /// and accepted by `verify` (directory, config, approval, source graph,
    /// engine compatibility). Every rejected candidate is reported.
    pub fn select_known_good(
        &self,
        authority: &DeploymentAuthority,
        failed_release_id: &str,
        now_secs: u64,
        verify: &dyn Fn(&ReleaseRecord) -> Result<()>,
    ) -> Result<KnownGoodSelection> {
        let mut seen = BTreeSet::new();
        seen.insert(failed_release_id.to_string());
        let mut refusals = Vec::new();
        for activation in self.activations(authority)?.iter().rev() {
            if !seen.insert(activation.release_id.clone()) {
                continue;
            }
            let release_id = activation.release_id.clone();
            let refuse = |reason: String| CandidateRefusal {
                release_id: release_id.clone(),
                reason,
            };
            let release = match self.release(authority, &release_id) {
                Ok(release) => release,
                Err(error) => {
                    refusals.push(refuse(format!("release record: {error:#}")));
                    continue;
                }
            };
            let health = match self.health(authority, &release_id) {
                Ok(health) => health,
                Err(error) => {
                    refusals.push(refuse(format!("release health: {error:#}")));
                    continue;
                }
            };
            if health.crash_looped() {
                refusals.push(refuse("release crash-looped before".to_string()));
                continue;
            }
            match health.last_healthy_at() {
                None => {
                    refusals.push(refuse("release never completed a healthy run".to_string()));
                    continue;
                }
                Some(last_healthy) if last_healthy > now_secs => {
                    refusals.push(refuse(format!(
                        "release readiness is dated in the future ({last_healthy} > {now_secs})"
                    )));
                    continue;
                }
                Some(_) => {}
            }
            if release.installed_at_epoch_secs > now_secs {
                refusals.push(refuse(
                    "release admission is dated in the future".to_string(),
                ));
                continue;
            }
            if let Err(error) = verify(&release) {
                refusals.push(refuse(format!("{error:#}")));
                continue;
            }
            return Ok(KnownGoodSelection {
                selected: Some(release),
                refusals,
            });
        }
        Ok(KnownGoodSelection {
            selected: None,
            refusals,
        })
    }

    /// Mark the failed release, select a known-good release under `policy`,
    /// commit the activation, and sign the outcome. Nothing is deleted.
    #[allow(clippy::too_many_arguments)]
    pub fn recover_from_crash_loop(
        &self,
        lock: &DeploymentLock,
        authority: &DeploymentAuthority,
        failed_release_id: &str,
        crash: CrashLoopEvidence,
        policy: &DeploymentPolicy,
        now_secs: u64,
        verify: &dyn Fn(&ReleaseRecord) -> Result<()>,
    ) -> Result<RecoveryRecord> {
        self.record_health(
            lock,
            authority,
            failed_release_id,
            HealthEvent::CrashLoop {
                evidence: crash.clone(),
            },
        )?;
        let sequence = self.recoveries(authority)?.len() as u64 + 1;
        anyhow::ensure!(
            sequence <= MAX_RECOVERIES,
            "deployment `{}` exceeds {MAX_RECOVERIES} recoveries",
            self.name
        );
        let (outcome, selected_release_id, activation_sequence, candidate_refusals) =
            match policy.on_crash_loop {
                CrashLoopAction::Contain => (RecoveryOutcome::Contained, None, None, Vec::new()),
                CrashLoopAction::Rollback => {
                    let selection =
                        self.select_known_good(authority, failed_release_id, now_secs, verify)?;
                    match selection.selected {
                        None => (
                            RecoveryOutcome::ContainedNoKnownGood,
                            None,
                            None,
                            selection.refusals,
                        ),
                        Some(release) => {
                            let activation = self.activate(
                                lock,
                                authority,
                                &release.release_id,
                                ActivationReason::CrashLoopRollback,
                                None,
                                Some(sequence),
                                now_secs,
                            )?;
                            (
                                RecoveryOutcome::RolledBack,
                                Some(release.release_id),
                                Some(activation.sequence),
                                selection.refusals,
                            )
                        }
                    }
                }
            };
        let recovery = RecoveryRecord {
            schema_version: RECOVERY_SCHEMA.to_string(),
            deployment: self.name.clone(),
            sequence,
            failed_release_id: failed_release_id.to_string(),
            crash,
            on_crash_loop: policy.on_crash_loop,
            restart: policy.restart,
            outcome,
            selected_release_id,
            activation_sequence,
            candidate_refusals,
            recorded_at_epoch_secs: now_secs,
        };
        write_new(
            &self.recovery_path(sequence),
            &authority.seal(recovery.clone())?,
        )?;
        Ok(recovery)
    }
}

/// SHA-256 of a file, as `sha256:<hex>`, bounded at `MAX_RECORD_BYTES`.
pub fn file_sha256(path: &Path) -> Result<String> {
    let bytes = read_bounded(path)?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(&bytes))))
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file(),
        "{} is not a regular file",
        path.display()
    );
    anyhow::ensure!(
        metadata.len() <= MAX_RECORD_BYTES,
        "{} exceeds {MAX_RECORD_BYTES} bytes",
        path.display()
    );
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("open {}", path.display()))?
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_RECORD_BYTES,
        "{} exceeds {MAX_RECORD_BYTES} bytes",
        path.display()
    );
    Ok(bytes)
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&read_bounded(path)?)
        .with_context(|| format!("decode deployment record {}", path.display()))
}

/// Create `path` exclusively; an existing record is never overwritten.
fn write_new<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    anyhow::ensure!(
        !path.exists(),
        "deployment record {} already exists",
        path.display()
    );
    write_replace(path, value)
}

/// Durably replace `path` (temp file, fsync, rename, directory fsync).
fn write_replace<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .context("deployment record path has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let bytes = serde_json::to_vec_pretty(value)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .context("deployment record name is not UTF-8")?,
        uuid::Uuid::now_v7()
    ));
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .with_context(|| format!("create {}", temporary.display()))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    fs::rename(&temporary, path)
        .with_context(|| format!("commit deployment record {}", path.display()))?;
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority(seed: u8) -> DeploymentAuthority {
        DeploymentAuthority::new(SigningKey::from_bytes(&[seed; 32]))
    }

    fn test_release(store: &DeploymentStore, id: &str) -> ReleaseRecord {
        // A release record only needs a structurally valid approval for the
        // store's own invariants; the CLI verifier re-authenticates real ones.
        let approval: PublisherSourceGraphApproval = serde_json::from_value(serde_json::json!({
            "manifest_path": "/registry/artifact.manifest.json",
            "manifest_sha256": format!("sha256:{}", "1".repeat(64)),
            "publisher_public_key_hex": "2".repeat(64),
            "identity": {
                "publisher_key_id": "key",
                "publisher_id": "publisher",
                "name": "app",
                "version": id,
                "artifact_sha256": format!("sha256:{}", "3".repeat(64)),
            },
            "capsule_digest": format!("sha256:{}", "4".repeat(64)),
            "graph_input_hash": format!("sha256:{}", "5".repeat(64)),
            "entrypoint": "app.js",
            "additional_conditions": [],
            "contained_symlinks": false,
        }))
        .expect("approval fixture");
        ReleaseRecord {
            schema_version: RELEASE_SCHEMA.to_string(),
            deployment: store.name().to_string(),
            release_id: id.to_string(),
            release_dir: PathBuf::from(format!("/releases/{id}")),
            entrypoint: "app.js".to_string(),
            config_sha256: format!("sha256:{}", "6".repeat(64)),
            registry_manifest: PathBuf::from("/registry/artifact.manifest.json"),
            publisher_public_key_path: PathBuf::from("/keys/publisher.pub"),
            approval,
            engine_compatibility: "franken-node/test".to_string(),
            installed_at_epoch_secs: 10,
        }
    }

    fn crash(nonce: &str) -> CrashLoopEvidence {
        CrashLoopEvidence {
            session_nonce: nonce.to_string(),
            entrypoint: "/releases/v2/app.js".to_string(),
            observed_at_epoch_secs: 100,
            crashes_in_window: 3,
            threshold: 3,
            window_secs: 60,
            safe_mode_state_path: "/releases/v2/.franken-node/safe-mode/state.json".to_string(),
        }
    }

    fn healthy(receipt: &str, at: u64) -> HealthEvent {
        HealthEvent::HealthyRun {
            receipt_id: receipt.to_string(),
            observed_at_epoch_secs: at,
        }
    }

    fn rollback_policy(store: &DeploymentStore) -> DeploymentPolicy {
        DeploymentPolicy {
            on_crash_loop: CrashLoopAction::Rollback,
            restart: RestartPolicy::Operator,
            operator_id: "ops".to_string(),
            ..DeploymentPolicy::contained_default(store.name())
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        store: DeploymentStore,
        authority: DeploymentAuthority,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = DeploymentStore::open(dir.path(), "app").expect("store");
        Fixture {
            _dir: dir,
            store,
            authority: authority(7),
        }
    }

    #[test]
    fn rollback_selects_the_newest_healthy_release_and_moves_only_the_pointer() {
        let f = fixture();
        let lock = f.store.lock().expect("lock");
        for id in ["v1", "v2"] {
            assert!(
                f.store
                    .install_release(&lock, &f.authority, test_release(&f.store, id))
                    .expect("install")
            );
        }
        f.store
            .activate(
                &lock,
                &f.authority,
                "v1",
                ActivationReason::Operator,
                Some("ops"),
                None,
                20,
            )
            .expect("activate v1");
        f.store
            .record_health(&lock, &f.authority, "v1", healthy("r-1", 30))
            .expect("healthy v1");
        f.store
            .activate(
                &lock,
                &f.authority,
                "v2",
                ActivationReason::Operator,
                Some("ops"),
                None,
                40,
            )
            .expect("activate v2");
        let recovery = f
            .store
            .recover_from_crash_loop(
                &lock,
                &f.authority,
                "v2",
                crash("n-1"),
                &rollback_policy(&f.store),
                100,
                &|_| Ok(()),
            )
            .expect("recover");
        assert_eq!(recovery.outcome, RecoveryOutcome::RolledBack);
        assert_eq!(recovery.selected_release_id.as_deref(), Some("v1"));
        let active = f
            .store
            .active(&f.authority)
            .expect("active")
            .expect("pointer");
        assert_eq!(active.release_id, "v1");
        assert_eq!(active.reason, ActivationReason::CrashLoopRollback);
        assert_eq!(active.recovery_sequence, Some(1));
        // Nothing is lost: both releases, the history and the crash mark remain.
        assert_eq!(f.store.release_ids().expect("ids"), vec!["v1", "v2"]);
        assert_eq!(f.store.activations(&f.authority).expect("chain").len(), 3);
        assert!(
            f.store
                .health(&f.authority, "v2")
                .expect("health")
                .crash_looped()
        );
    }

    #[test]
    fn rollback_refuses_unverified_unhealthy_and_crash_looped_candidates() {
        let f = fixture();
        let lock = f.store.lock().expect("lock");
        for id in ["v1", "v2", "v3", "v4"] {
            f.store
                .install_release(&lock, &f.authority, test_release(&f.store, id))
                .expect("install");
        }
        // v1 healthy but rejected by the verifier; v2 never healthy; v3
        // crash-looped before; v4 is the failing release.
        for (id, health) in [
            ("v1", Some(healthy("r-1", 30))),
            ("v2", None),
            ("v3", Some(healthy("r-3", 31))),
        ] {
            f.store
                .activate(
                    &lock,
                    &f.authority,
                    id,
                    ActivationReason::Operator,
                    Some("ops"),
                    None,
                    20,
                )
                .expect("activate");
            if let Some(health) = health {
                f.store
                    .record_health(&lock, &f.authority, id, health)
                    .expect("health");
            }
        }
        f.store
            .record_health(
                &lock,
                &f.authority,
                "v3",
                HealthEvent::CrashLoop {
                    evidence: crash("n-0"),
                },
            )
            .expect("v3 crash mark");
        f.store
            .activate(
                &lock,
                &f.authority,
                "v4",
                ActivationReason::Operator,
                Some("ops"),
                None,
                50,
            )
            .expect("activate v4");
        let recovery = f
            .store
            .recover_from_crash_loop(
                &lock,
                &f.authority,
                "v4",
                crash("n-1"),
                &rollback_policy(&f.store),
                100,
                &|release| {
                    anyhow::ensure!(
                        release.release_id != "v1",
                        "source graph changed after admission"
                    );
                    Ok(())
                },
            )
            .expect("recover");
        assert_eq!(recovery.outcome, RecoveryOutcome::ContainedNoKnownGood);
        assert_eq!(recovery.activation_sequence, None);
        let reasons: Vec<_> = recovery
            .candidate_refusals
            .iter()
            .map(|refusal| (refusal.release_id.as_str(), refusal.reason.as_str()))
            .collect();
        assert_eq!(
            reasons,
            vec![
                ("v3", "release crash-looped before"),
                ("v2", "release never completed a healthy run"),
                ("v1", "source graph changed after admission"),
            ]
        );
        // The pointer stays on the failed release: containment, not a switch.
        assert_eq!(
            f.store
                .active(&f.authority)
                .expect("active")
                .expect("pointer")
                .release_id,
            "v4"
        );
    }

    #[test]
    fn contain_policy_records_the_crash_without_switching() {
        let f = fixture();
        let lock = f.store.lock().expect("lock");
        for id in ["v1", "v2"] {
            f.store
                .install_release(&lock, &f.authority, test_release(&f.store, id))
                .expect("install");
        }
        f.store
            .activate(
                &lock,
                &f.authority,
                "v1",
                ActivationReason::Operator,
                Some("ops"),
                None,
                20,
            )
            .expect("activate");
        f.store
            .record_health(&lock, &f.authority, "v1", healthy("r-1", 30))
            .expect("health");
        f.store
            .activate(
                &lock,
                &f.authority,
                "v2",
                ActivationReason::Operator,
                Some("ops"),
                None,
                40,
            )
            .expect("activate");
        let policy = f.store.policy(&f.authority).expect("default policy");
        assert_eq!(policy.on_crash_loop, CrashLoopAction::Contain);
        let recovery = f
            .store
            .recover_from_crash_loop(
                &lock,
                &f.authority,
                "v2",
                crash("n-1"),
                &policy,
                100,
                &|_| Ok(()),
            )
            .expect("recover");
        assert_eq!(recovery.outcome, RecoveryOutcome::Contained);
        assert_eq!(
            f.store
                .active(&f.authority)
                .expect("active")
                .expect("ptr")
                .release_id,
            "v2"
        );
    }

    #[test]
    fn tampered_pointer_foreign_signer_and_edited_records_are_refused() {
        let f = fixture();
        let lock = f.store.lock().expect("lock");
        f.store
            .install_release(&lock, &f.authority, test_release(&f.store, "v1"))
            .expect("install");
        f.store
            .activate(
                &lock,
                &f.authority,
                "v1",
                ActivationReason::Operator,
                Some("ops"),
                None,
                20,
            )
            .expect("activate");
        // A different authority cannot read (or forge) this deployment.
        assert!(f.store.active(&authority(8)).is_err());
        // Editing the signed pointer breaks its signature.
        let pointer = f.store.root().join("active.json");
        let edited = fs::read_to_string(&pointer)
            .expect("pointer")
            .replace("\"v1\"", "\"v9\"");
        fs::write(&pointer, edited).expect("edit pointer");
        let error = f.store.active(&f.authority).expect_err("edited pointer");
        assert!(format!("{error:#}").contains("signature"), "{error:#}");
        // Re-installing different content under an existing id is refused.
        let mut changed = test_release(&f.store, "v1");
        changed.entrypoint = "other.js".to_string();
        assert!(
            f.store
                .install_release(&lock, &f.authority, changed)
                .is_err()
        );
        assert!(
            !f.store
                .install_release(&lock, &f.authority, test_release(&f.store, "v1"))
                .expect("identical reinstall is idempotent")
        );
    }

    #[test]
    fn identifiers_are_bounded_and_path_free() {
        for bad in ["", ".hidden", "a/b", "..", "with space", &"x".repeat(65)] {
            assert!(validate_identifier("release id", bad).is_err(), "{bad:?}");
        }
        for good in ["v1", "app-2026.11.06", "a_b"] {
            validate_identifier("release id", good).expect(good);
        }
    }

    #[test]
    fn healthy_runs_are_deduplicated_and_crash_marks_are_never_evicted() {
        let f = fixture();
        let lock = f.store.lock().expect("lock");
        f.store
            .install_release(&lock, &f.authority, test_release(&f.store, "v1"))
            .expect("install");
        f.store
            .record_health(&lock, &f.authority, "v1", healthy("r-1", 30))
            .expect("first");
        let health = f
            .store
            .record_health(&lock, &f.authority, "v1", healthy("r-1", 31))
            .expect("duplicate");
        assert_eq!(health.healthy_runs(), 1);
        f.store
            .record_health(
                &lock,
                &f.authority,
                "v1",
                HealthEvent::CrashLoop {
                    evidence: crash("n-1"),
                },
            )
            .expect("crash");
        for index in 0..MAX_HEALTH_EVENTS + 4 {
            f.store
                .record_health(
                    &lock,
                    &f.authority,
                    "v1",
                    healthy(&format!("r-{index}-x"), 40),
                )
                .expect("healthy");
        }
        let health = f.store.health(&f.authority, "v1").expect("health");
        assert_eq!(health.events.len(), MAX_HEALTH_EVENTS);
        assert!(health.crash_looped());
    }
}
