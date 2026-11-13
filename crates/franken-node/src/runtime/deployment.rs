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

use std::collections::{BTreeMap, BTreeSet};
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
const SUPERSESSION_ACTIVATION_SCHEMA: &str = "franken-node/deployment-activation/v2";
pub const HEALTH_SCHEMA: &str = "franken-node/deployment-release-health/v1";
pub const RECOVERY_SCHEMA: &str = "franken-node/deployment-recovery/v1";
const TRANSACTION_SCHEMA: &str = "franken-node/deployment-activation-transaction/v1";
const SUPERSESSION_TRANSACTION_SCHEMA: &str = "franken-node/deployment-activation-transaction/v2";

/// Domain separator for every deployment record signature.
const SIGNATURE_DOMAIN: &[u8] = b"franken-node:deployment-record:v1\0";
/// Releases retained per deployment.
pub const MAX_RELEASES: usize = 256;
/// Activations retained per deployment (the chain is verified end to end).
pub const MAX_ACTIVATIONS: u64 = 4_096;
/// Recoveries retained per deployment.
pub const MAX_RECOVERIES: u64 = 4_096;
/// Health events retained per release; the oldest healthy runs are evicted
/// first; native panic and crash-loop marks are never evicted.
pub const MAX_HEALTH_EVENTS: usize = 512;
/// Reserve one retained event for the threshold-crossing crash-loop mark.
pub const MAX_DEPLOYMENT_CRASH_THRESHOLD: u32 = (MAX_HEALTH_EVENTS - 1) as u32;
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
    /// A v2 activation requires its matching supersession intent forever.
    /// Omitting the field preserves historical v1 signature preimages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_transaction_digest: Option<String>,
}

/// One launch-bound panic authenticated against the protected native inventory.
/// The caller must authenticate its admission and outcome before signing it
/// into this release's history. Original observation times are never refreshed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePanicEvidence {
    pub session_nonce: String,
    pub entrypoint: String,
    pub observed_at_epoch_secs: u64,
    pub no_admitted_host_effects: bool,
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
    /// An independently authenticated native panic from this exact release.
    NativePanic { evidence: NativePanicEvidence },
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
                HealthEvent::NativePanic { .. } | HealthEvent::CrashLoop { .. } => None,
            })
            .max()
    }

    /// An unresolved admitted effect remains a recovery blocker even after its
    /// panic leaves the counting window. A later clean panic cannot erase it.
    #[must_use]
    pub fn has_indeterminate_native_effects(&self) -> bool {
        self.events.iter().any(|event| {
            matches!(event, HealthEvent::NativePanic { evidence }
                if !evidence.no_admitted_host_effects)
        })
    }

    /// Derive a threshold crossing solely from signed, deduplicated launch
    /// observations. The unsigned local safe-mode counter is never an input.
    pub fn native_crash_loop_evidence(
        &self,
        session_nonce: &str,
        threshold: u32,
        window_secs: u64,
        safe_mode_state_path: &Path,
    ) -> Result<Option<CrashLoopEvidence>> {
        anyhow::ensure!(
            threshold > 0
                && threshold <= MAX_DEPLOYMENT_CRASH_THRESHOLD
                && window_secs > 0
                && window_secs <= 86_400,
            "deployment crash-window policy exceeds its retained history or native detector bounds"
        );
        let current = self
            .events
            .iter()
            .find_map(|event| match event {
                HealthEvent::NativePanic { evidence }
                    if evidence.session_nonce == session_nonce =>
                {
                    Some(evidence)
                }
                _ => None,
            })
            .context("deployment crash window has no authenticated current panic")?;
        let mut seen = BTreeSet::new();
        let mut count = 0_u32;
        for event in &self.events {
            let HealthEvent::NativePanic { evidence } = event else {
                continue;
            };
            anyhow::ensure!(
                evidence.entrypoint == current.entrypoint
                    && evidence.observed_at_epoch_secs <= current.observed_at_epoch_secs
                    && seen.insert(&evidence.session_nonce),
                "deployment panic history has a foreign entrypoint, duplicate identity or clock rollback"
            );
            if current.observed_at_epoch_secs - evidence.observed_at_epoch_secs <= window_secs {
                count = count
                    .checked_add(1)
                    .context("deployment panic count overflow")?;
            }
        }
        Ok((count >= threshold).then(|| CrashLoopEvidence {
            session_nonce: current.session_nonce.clone(),
            entrypoint: current.entrypoint.clone(),
            observed_at_epoch_secs: current.observed_at_epoch_secs,
            crashes_in_window: count,
            threshold,
            window_secs,
            safe_mode_state_path: safe_mode_state_path.display().to_string(),
        }))
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
    /// A prior authenticated panic may have committed an external effect.
    /// Neither activation nor automatic restart is authorized by recovery.
    ContainedEffectsIndeterminate,
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

/// A retained, signed authorization to finish exactly one activation. The
/// pointer is committed last, after both the history and recovery (if any).
/// An interrupted transaction can be completed only by explicit reconciliation
/// with a fresh verification of the target release and unchanged recovery policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationTransaction {
    schema_version: String,
    deployment: String,
    activation: ActivationRecord,
    recovery: Option<RecoveryRecord>,
    recovery_policy: Option<DeploymentPolicy>,
    /// Omitted for v1 so historical signature preimages remain byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    supersedes: Option<SupersessionAuthority>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SupersessionAuthority {
    superseded_sequence: u64,
    superseded_transaction_digest: String,
    /// Zero denotes the empty committed prefix, before the first activation.
    committed_sequence: u64,
    committed_activation_digest: Option<String>,
    reason: String,
}

struct AuthenticatedTransaction {
    payload: ActivationTransaction,
    digest: String,
}

/// An authenticated operation that has not yet published its activation
/// pointer. This is an inspectable plan, not authority to execute a release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingActivation {
    pub transaction_digest: String,
    pub activation: ActivationRecord,
    pub planned_recovery: Option<RecoveryRecord>,
}

/// A canceled attempt retained in the raw signed journals. It never appears
/// in the effective activation or recovery history and cannot establish readiness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupersededActivation {
    pub transaction_digest: String,
    pub activation: ActivationRecord,
    pub planned_recovery: Option<RecoveryRecord>,
    pub superseded_by_sequence: u64,
    pub superseded_by_operator_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentSupersedeOutcome {
    pub activation: ActivationRecord,
    pub already_committed: bool,
    pub superseded_transaction_digest: String,
}

/// Read-only deployment history, including an interrupted signed operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentActivationStatus {
    pub activations: Vec<ActivationRecord>,
    pub pending: Option<PendingActivation>,
    pub superseded: Vec<SupersededActivation>,
}

struct ActivationState {
    committed: Vec<ActivationRecord>,
    recoveries: Vec<RecoveryRecord>,
    pending: Option<ActivationTransaction>,
    pending_digest: Option<String>,
    superseded: Vec<SupersededActivation>,
    transactions: Vec<AuthenticatedTransaction>,
    recovery_high_water: u64,
    consumed_crash_nonces: BTreeSet<String>,
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

fn validate_supersession_reason(reason: &str) -> Result<()> {
    anyhow::ensure!(
        !reason.trim().is_empty() && reason.len() <= MAX_REASON_BYTES,
        "supersession reason must be non-empty and at most {MAX_REASON_BYTES} bytes"
    );
    Ok(())
}

/// Exclusive advisory lock over one deployment's state.
pub struct DeploymentLock {
    _file: File,
    store_root: PathBuf,
}

/// Read-only continuation restriction for one already admitted activation.
/// This record adds no execution authority and contains no operator secret.
/// Every field travels in the authenticated native-worker configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationRestriction {
    schema_version: String,
    store_root: PathBuf,
    deployment: String,
    activation_sequence: u64,
    release_id: String,
    release_dir: PathBuf,
    config_sha256: String,
    approval_sha256: String,
    activation_digest: String,
    pointer_sha256: String,
    signer_public_key_hex: String,
    directories: Vec<RestrictedDirectoryIdentity>,
    activations: RestrictedHistory,
    transactions: Option<RestrictedHistory>,
}

const ACTIVATION_RESTRICTION_SCHEMA: &str = "franken-node/deployment-activation-restriction/v1";
const MAX_RESTRICTION_PATH_BYTES: usize = 4096;
const MAX_RESTRICTION_PATH_COMPONENTS: usize = 128;
/// Maximum committed record bytes inspected in one history observation.
#[cfg(unix)]
const MAX_RESTRICTION_HISTORY_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestrictedDirectoryIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestrictedDirectoryRevision {
    modified_secs: i64,
    modified_nanos: i64,
    changed_secs: i64,
    changed_nanos: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestrictedHistory {
    directory: RestrictedDirectoryIdentity,
    revision: RestrictedDirectoryRevision,
    entries_sha256: String,
    record_count: u64,
}

impl ActivationRestriction {
    #[must_use]
    pub fn store_root(&self) -> &Path {
        &self.store_root
    }

    #[must_use]
    pub fn deployment(&self) -> &str {
        &self.deployment
    }

    #[must_use]
    pub fn activation_sequence(&self) -> u64 {
        self.activation_sequence
    }

    #[must_use]
    pub fn release_id(&self) -> &str {
        &self.release_id
    }

    /// Validate the bounded restriction without opening state or granting
    /// authority. Filesystem observations are checked separately by enforce.
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.schema_version == ACTIVATION_RESTRICTION_SCHEMA,
            "unsupported deployment activation restriction"
        );
        validate_identifier("restricted deployment", &self.deployment)?;
        validate_identifier("restricted release", &self.release_id)?;
        let components = restriction_path_shape(&self.store_root)?;
        restriction_path_shape(&self.release_dir)?;
        anyhow::ensure!(
            self.store_root
                .ends_with(Path::new(DEPLOYMENTS_RELATIVE_DIR).join(&self.deployment))
                && self.directories.len() == components
                && (1..=MAX_ACTIVATIONS).contains(&self.activation_sequence),
            "deployment activation restriction has an invalid path or sequence"
        );
        for digest in [
            &self.config_sha256,
            &self.approval_sha256,
            &self.activation_digest,
            &self.pointer_sha256,
            &self.activations.entries_sha256,
        ] {
            anyhow::ensure!(
                restriction_hash(digest),
                "deployment activation restriction has an invalid commitment"
            );
        }
        for history in std::iter::once(&self.activations).chain(self.transactions.as_ref()) {
            anyhow::ensure!(
                history.record_count <= self.activation_sequence
                    && restriction_hash(&history.entries_sha256)
                    && (0..1_000_000_000).contains(&history.revision.modified_nanos)
                    && (0..1_000_000_000).contains(&history.revision.changed_nanos),
                "deployment activation restriction has invalid history bounds"
            );
        }
        anyhow::ensure!(
            self.activations.record_count == self.activation_sequence,
            "deployment activation restriction omits its admitted history"
        );
        self.verifying_key()?;
        Ok(())
    }

    /// A caller-supplied restriction must describe this exact admitted release,
    /// not another valid deployment. These are bindings, never new run grants.
    pub fn validate_release(
        &self,
        release_root: &Path,
        config_sha256: &str,
        approval_sha256: &str,
    ) -> Result<()> {
        self.validate_source(release_root, approval_sha256)?;
        anyhow::ensure!(
            config_sha256 == self.config_sha256,
            "deployment activation restriction does not match the admitted configuration"
        );
        Ok(())
    }

    /// Bind a direct library/worker dispatch to its admitted source without
    /// consulting mutable activation state or claiming configuration admission.
    pub fn validate_source(&self, release_root: &Path, approval_sha256: &str) -> Result<()> {
        self.validate()?;
        anyhow::ensure!(
            release_root == self.release_dir.as_path() && approval_sha256 == self.approval_sha256,
            "deployment activation restriction does not match the admitted source"
        );
        Ok(())
    }

    fn verifying_key(&self) -> Result<VerifyingKey> {
        anyhow::ensure!(
            self.signer_public_key_hex.len() == 64
                && self
                    .signer_public_key_hex
                    .bytes()
                    .all(|byte| { byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) }),
            "deployment activation restriction has an invalid public key"
        );
        let bytes: [u8; 32] = hex::decode(&self.signer_public_key_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid deployment public key length"))?;
        VerifyingKey::from_bytes(&bytes).context("invalid deployment public key")
    }

    #[cfg(unix)]
    fn check_pointer(&self, bytes: &[u8]) -> Result<()> {
        anyhow::ensure!(
            restriction_bytes_hash(bytes) == self.pointer_sha256,
            "deployment activation pointer changed after admission"
        );
        let record: SignedRecord<ActivationRecord> =
            serde_json::from_slice(bytes).context("invalid deployment activation pointer")?;
        validate_activation_shape(&record.payload)?;
        anyhow::ensure!(
            record.signer_public_key_hex == self.signer_public_key_hex
                && record.payload.deployment == self.deployment
                && record.payload.sequence == self.activation_sequence
                && record.payload.release_id == self.release_id
                && record_digest(&record)? == self.activation_digest,
            "deployment activation pointer no longer matches its admission"
        );
        let signature: [u8; 64] = hex::decode(&record.signature_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid deployment activation signature length"))?;
        self.verifying_key()?
            .verify_strict(
                &signing_message(&record.payload)?,
                &Signature::from_bytes(&signature),
            )
            .context("deployment activation signature no longer verifies")
    }

    /// Require the exact admitted pointer and immutable history observation.
    /// A new transaction intent retires this activation before its pointer
    /// commits. Interrupted transitions and restored old pointer bytes cannot
    /// erase the retained history obligation. No replacement state is trusted.
    ///
    /// Reads are bounded, descriptor-relative and do not follow symlinks. The
    /// observer must latch any refusal and request native-session termination;
    /// these polling observations do not constitute an atomic fleet barrier.
    pub fn enforce(&self) -> Result<()> {
        self.validate()?;
        #[cfg(not(unix))]
        anyhow::bail!("deployment activation retirement requires Unix directory handles");
        #[cfg(unix)]
        {
            // Reopen from the filesystem root for each observation. An owned
            // descriptor alone could continue watching a renamed, obsolete tree.
            // Repeat the observation to detect retargeting during the read.
            for _ in 0..2 {
                let (directory, identities) = open_restricted_directory(&self.store_root)?;
                anyhow::ensure!(
                    identities == self.directories,
                    "deployment state directory changed after admission"
                );
                let pointer = read_restricted_pointer(&directory)?;
                self.check_pointer(&pointer)?;
                anyhow::ensure!(
                    inspect_restricted_history(
                        &directory,
                        "activations",
                        self.activation_sequence,
                    )?
                    .as_ref()
                        == Some(&self.activations)
                        && inspect_restricted_history(
                            &directory,
                            "transactions",
                            self.activation_sequence,
                        )? == self.transactions,
                    "deployment activation history or transaction intent changed after admission"
                );
            }
            Ok(())
        }
    }
}

fn restriction_path_shape(path: &Path) -> Result<usize> {
    let components = path.components().count();
    let normalized: PathBuf = path.components().collect();
    anyhow::ensure!(
        path.is_absolute()
            && path.as_os_str().len() <= MAX_RESTRICTION_PATH_BYTES
            && (1..=MAX_RESTRICTION_PATH_COMPONENTS).contains(&components)
            && path.components().all(|part| {
                matches!(
                    part,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
            && normalized.as_os_str() == path.as_os_str(),
        "deployment activation restriction requires a bounded normalized absolute path"
    );
    Ok(components)
}

fn restriction_hash(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[cfg(unix)]
fn restriction_bytes_hash(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(unix)]
fn restricted_directory_identity(metadata: &fs::Metadata) -> RestrictedDirectoryIdentity {
    use std::os::unix::fs::MetadataExt as _;
    RestrictedDirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(unix)]
fn restricted_directory_revision(metadata: &fs::Metadata) -> RestrictedDirectoryRevision {
    use std::os::unix::fs::MetadataExt as _;
    RestrictedDirectoryRevision {
        modified_secs: metadata.mtime(),
        modified_nanos: metadata.mtime_nsec(),
        changed_secs: metadata.ctime(),
        changed_nanos: metadata.ctime_nsec(),
    }
}

#[cfg(unix)]
fn open_restricted_directory(path: &Path) -> Result<(File, Vec<RestrictedDirectoryIdentity>)> {
    use rustix::fs::{Mode, OFlags, open, openat};
    restriction_path_shape(path)?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = File::from(open("/", flags, Mode::empty())?);
    let mut identities = vec![restricted_directory_identity(&directory.metadata()?)];
    for part in path.components() {
        if let std::path::Component::Normal(name) = part {
            directory = File::from(openat(&directory, name, flags, Mode::empty())?);
            identities.push(restricted_directory_identity(&directory.metadata()?));
        }
    }
    Ok((directory, identities))
}

#[cfg(unix)]
fn read_restricted_pointer(directory: &File) -> Result<Vec<u8>> {
    use rustix::fs::{Mode, OFlags, openat};
    let file = File::from(openat(
        directory,
        "active.json",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let before = file.metadata()?;
    anyhow::ensure!(
        before.is_file() && before.len() <= MAX_RECORD_BYTES,
        "deployment activation pointer is not a bounded regular file"
    );
    let mut bytes = Vec::new();
    (&file).take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    anyhow::ensure!(
        bytes.len() as u64 == before.len()
            && before.len() == after.len()
            && restricted_directory_identity(&before) == restricted_directory_identity(&after)
            && restricted_directory_revision(&before) == restricted_directory_revision(&after),
        "deployment activation pointer changed during inspection"
    );
    Ok(bytes)
}

#[cfg(unix)]
fn inspect_restricted_history(
    store: &File,
    name: &str,
    admitted_sequence: u64,
) -> Result<Option<RestrictedHistory>> {
    use rustix::fs::{Dir, Mode, OFlags, openat};
    let directory = match openat(
        store,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(file) => File::from(file),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error).context("cannot inspect deployment activation history"),
    };
    let before = directory.metadata()?;
    let mut observations = BTreeMap::new();
    let mut records = 0_u64;
    let mut history_bytes = 0_u64;
    for (index, entry) in Dir::read_from(&directory)?.enumerate() {
        anyhow::ensure!(
            (index as u64) < MAX_ACTIVATIONS * 4,
            "deployment activation restriction history exceeds its entry bound"
        );
        let entry = entry?;
        let name = entry
            .file_name()
            .to_str()
            .context("invalid deployment history filename")?;
        anyhow::ensure!(
            name.len() <= 256,
            "deployment history filename exceeds its byte bound"
        );
        if matches!(name, "." | "..") {
            continue;
        }
        let temporary = name.starts_with('.') && name.ends_with(".tmp");
        if !temporary {
            let sequence = name
                .strip_suffix(".json")
                .and_then(|sequence| sequence.parse::<u64>().ok())
                .filter(|sequence| (1..=MAX_ACTIVATIONS).contains(sequence))
                .context("invalid deployment activation history filename")?;
            anyhow::ensure!(
                name == format!("{sequence:010}.json") && sequence <= admitted_sequence,
                "a newer deployment activation or transaction intent retires this run"
            );
        }
        let file = File::from(openat(
            &directory,
            entry.file_name(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file() && metadata.len() <= MAX_RECORD_BYTES,
            "deployment history entry is not a bounded regular file"
        );
        // The capture authenticates complete signed history. Polling commits
        // to its exact bytes without repeating every signature verification.
        // Timestamps alone cannot notice same-size edits in one clock tick.
        let content_sha256 = if temporary {
            None
        } else {
            history_bytes = history_bytes
                .checked_add(metadata.len())
                .context("deployment history byte count overflow")?;
            anyhow::ensure!(
                history_bytes <= MAX_RESTRICTION_HISTORY_BYTES,
                "deployment activation restriction history exceeds its byte bound"
            );
            let mut bytes = Vec::new();
            (&file).take(metadata.len() + 1).read_to_end(&mut bytes)?;
            anyhow::ensure!(
                bytes.len() as u64 == metadata.len(),
                "deployment history entry changed length during inspection"
            );
            records += 1;
            let digest: [u8; 32] = Sha256::digest(&bytes).into();
            Some(digest)
        };
        let after = file.metadata()?;
        anyhow::ensure!(
            metadata.len() == after.len()
                && restricted_directory_identity(&metadata)
                    == restricted_directory_identity(&after)
                && restricted_directory_revision(&metadata)
                    == restricted_directory_revision(&after),
            "deployment history entry changed during inspection"
        );
        anyhow::ensure!(
            observations
                .insert(
                    name.to_owned(),
                    (
                        restricted_directory_identity(&metadata),
                        restricted_directory_revision(&metadata),
                        metadata.len(),
                        content_sha256,
                    ),
                )
                .is_none(),
            "deployment activation history changed during enumeration"
        );
    }
    let after = directory.metadata()?;
    anyhow::ensure!(
        restricted_directory_identity(&before) == restricted_directory_identity(&after)
            && restricted_directory_revision(&before) == restricted_directory_revision(&after),
        "deployment activation history changed during inspection"
    );
    let mut digest = Sha256::new();
    digest.update(b"franken-node/deployment-restriction-history/v1\0");
    digest.update((name.len() as u64).to_le_bytes());
    digest.update(name.as_bytes());
    for (entry, (identity, revision, length, content_sha256)) in observations {
        digest.update((entry.len() as u64).to_le_bytes());
        digest.update(entry.as_bytes());
        digest.update(identity.device.to_le_bytes());
        digest.update(identity.inode.to_le_bytes());
        digest.update(length.to_le_bytes());
        digest.update(revision.modified_secs.to_le_bytes());
        digest.update(revision.modified_nanos.to_le_bytes());
        digest.update(revision.changed_secs.to_le_bytes());
        digest.update(revision.changed_nanos.to_le_bytes());
        if let Some(content_sha256) = content_sha256 {
            digest.update([1]);
            digest.update(content_sha256);
        } else {
            // Temporary entry names and metadata restrict continuation, but
            // incomplete staging payloads are not authenticated history.
            digest.update([0]);
        }
    }
    Ok(Some(RestrictedHistory {
        directory: restricted_directory_identity(&before),
        revision: restricted_directory_revision(&before),
        entries_sha256: format!("sha256:{}", hex::encode(digest.finalize())),
        record_count: records,
    }))
}

/// Filesystem store for one deployment.
pub struct DeploymentStore {
    name: String,
    project_root: PathBuf,
    root: PathBuf,
}

impl DeploymentStore {
    /// Open (without creating) the store of `name` under `deployment_root`.
    pub fn open(deployment_root: &Path, name: &str) -> Result<Self> {
        validate_identifier("deployment name", name)?;
        Ok(Self {
            name: name.to_string(),
            project_root: deployment_root.to_path_buf(),
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

    /// Operator project whose fleet controls govern every supervised release,
    /// including releases stored outside this project's directory tree.
    #[must_use]
    pub fn project_root(&self) -> &Path {
        &self.project_root
    }

    /// Serialize every read-modify-write of this deployment.
    pub fn lock(&self) -> Result<DeploymentLock> {
        use fs2::FileExt as _;
        create_durable_directory(&self.root)
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
        Ok(DeploymentLock {
            _file: file,
            store_root: self.root.canonicalize()?,
        })
    }

    fn require_lock(&self, lock: &DeploymentLock) -> Result<()> {
        anyhow::ensure!(
            lock.store_root == self.root.canonicalize()?,
            "deployment lock belongs to a different store"
        );
        Ok(())
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

    fn transaction_path(&self, sequence: u64) -> PathBuf {
        self.root
            .join("transactions")
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
        lock: &DeploymentLock,
        authority: &DeploymentAuthority,
        release: ReleaseRecord,
    ) -> Result<bool> {
        self.require_lock(lock)?;
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
        lock: &DeploymentLock,
        authority: &DeploymentAuthority,
        policy: DeploymentPolicy,
    ) -> Result<()> {
        self.require_lock(lock)?;
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

    fn activation_history(
        &self,
        authority: &DeploymentAuthority,
    ) -> Result<Vec<SignedRecord<ActivationRecord>>> {
        let mut chain = Vec::new();
        let mut previous_digest: Option<String> = None;
        for sequence in record_sequences(&self.root.join("activations"), MAX_ACTIVATIONS, true)? {
            let record: SignedRecord<ActivationRecord> =
                read_json(&self.activation_path(sequence))?;
            authority.open(&record, "activation record")?;
            let activation = &record.payload;
            anyhow::ensure!(
                activation.deployment == self.name
                    && activation.sequence == sequence
                    && activation.previous_activation_digest == previous_digest,
                "activation chain of deployment `{}` is broken at sequence {sequence}",
                self.name
            );
            validate_activation_shape(activation)?;
            previous_digest = Some(record_digest(&record)?);
            chain.push(record);
        }
        Ok(chain)
    }

    fn pointer(&self, authority: &DeploymentAuthority) -> Result<Option<ActivationRecord>> {
        let path = self.pointer_path();
        if !path.try_exists()? {
            return Ok(None);
        }
        let record: SignedRecord<ActivationRecord> = read_json(&path)?;
        authority.open(&record, "activation pointer")?;
        Ok(Some(record.payload))
    }

    fn transactions(
        &self,
        authority: &DeploymentAuthority,
    ) -> Result<Vec<AuthenticatedTransaction>> {
        let mut transactions = Vec::new();
        for sequence in record_sequences(&self.root.join("transactions"), MAX_ACTIVATIONS, false)? {
            let record: SignedRecord<ActivationTransaction> =
                read_json(&self.transaction_path(sequence))?;
            authority.open(&record, "activation transaction")?;
            let digest = record_digest(&record)?;
            let transaction = record.payload;
            anyhow::ensure!(
                ((transaction.schema_version == TRANSACTION_SCHEMA
                    && transaction.supersedes.is_none())
                    || (transaction.schema_version == SUPERSESSION_TRANSACTION_SCHEMA
                        && transaction.supersedes.is_some()))
                    && transaction.deployment == self.name
                    && transaction.activation.deployment == self.name
                    && transaction.activation.sequence == sequence,
                "activation transaction does not belong to deployment `{}` sequence {sequence}",
                self.name
            );
            validate_activation_shape(&transaction.activation)?;
            anyhow::ensure!(
                transaction
                    .activation
                    .supersedes_transaction_digest
                    .as_deref()
                    == transaction
                        .supersedes
                        .as_ref()
                        .map(|supersedes| supersedes.superseded_transaction_digest.as_str()),
                "activation supersession marker differs from its signed intent"
            );
            if let Some(supersedes) = &transaction.supersedes {
                anyhow::ensure!(
                    transaction.activation.reason == ActivationReason::Operator
                        && transaction.recovery.is_none()
                        && transaction.recovery_policy.is_none()
                        && supersedes.superseded_sequence.checked_add(1) == Some(sequence)
                        && supersedes.committed_sequence < supersedes.superseded_sequence,
                    "supersession must replace the immediately preceding uncommitted attempt with an operator activation"
                );
                validate_supersession_reason(&supersedes.reason)?;
            }
            match (&transaction.recovery, &transaction.recovery_policy) {
                (None, None) => anyhow::ensure!(
                    transaction.activation.reason == ActivationReason::Operator,
                    "rollback transaction lacks its recovery authorization"
                ),
                (Some(recovery), Some(policy)) => {
                    validate_recovery_link(&transaction.activation, recovery)?;
                    anyhow::ensure!(
                        policy.schema_version == POLICY_SCHEMA
                            && policy.deployment == self.name
                            && policy.on_crash_loop == CrashLoopAction::Rollback
                            && recovery.on_crash_loop == policy.on_crash_loop
                            && recovery.restart == policy.restart,
                        "rollback transaction has inconsistent policy authority"
                    );
                    validate_operator_id(&policy.operator_id)?;
                }
                _ => anyhow::bail!("activation transaction has incomplete recovery authority"),
            }
            transactions.push(AuthenticatedTransaction {
                payload: transaction,
                digest,
            });
        }
        Ok(transactions)
    }

    /// Authenticate raw attempt journals before deriving effective history.
    /// Multiple uncommitted intents are allowed only as an exact, bounded,
    /// signed supersession chain. Reading never grants the canceled targets.
    fn activation_state(&self, authority: &DeploymentAuthority) -> Result<ActivationState> {
        let raw_chain = self.activation_history(authority)?;
        let pointer = self.pointer(authority)?;
        let committed_sequence = pointer.as_ref().map_or(0, |record| record.sequence);
        if let Some(pointer) = &pointer {
            anyhow::ensure!(
                raw_chain.iter().any(|record| &record.payload == pointer),
                "activation pointer is not an authenticated history link"
            );
        }
        let transactions = self.transactions(authority)?;
        let by_sequence: BTreeMap<_, _> = transactions
            .iter()
            .map(|record| (record.payload.activation.sequence, record))
            .collect();
        for record in &raw_chain {
            if record.payload.supersedes_transaction_digest.is_some() {
                anyhow::ensure!(
                    by_sequence
                        .get(&record.payload.sequence)
                        .is_some_and(|transaction| transaction.payload.activation
                            == record.payload
                            && transaction.payload.supersedes.is_some()),
                    "superseding activation is missing its exact signed transaction"
                );
            }
        }
        let mut conceptual = BTreeMap::new();
        let mut activation_digests = BTreeMap::new();
        for record in &raw_chain {
            conceptual.insert(record.payload.sequence, record.payload.clone());
            activation_digests.insert(record.payload.sequence, record_digest(record)?);
        }
        for record in &transactions {
            let activation = &record.payload.activation;
            if let Some(existing) = conceptual.get(&activation.sequence) {
                anyhow::ensure!(
                    existing == activation,
                    "partial activation history differs from its signed intent"
                );
            } else {
                conceptual.insert(activation.sequence, activation.clone());
                activation_digests.insert(
                    activation.sequence,
                    record_digest(&authority.seal(activation.clone())?)?,
                );
            }
        }
        let mut previous_digest = None;
        for (index, (sequence, activation)) in conceptual.iter().enumerate() {
            anyhow::ensure!(
                *sequence == index as u64 + 1
                    && activation.previous_activation_digest == previous_digest,
                "activation intent has a different predecessor or sequence gap"
            );
            previous_digest = activation_digests.get(sequence).cloned();
        }

        let mut superseded_by = BTreeMap::new();
        for record in &transactions {
            let transaction = &record.payload;
            let Some(supersedes) = &transaction.supersedes else {
                continue;
            };
            let original = by_sequence
                .get(&supersedes.superseded_sequence)
                .context("supersession lacks the authenticated original intent")?;
            anyhow::ensure!(
                original.digest == supersedes.superseded_transaction_digest
                    && transaction.activation.activated_at_epoch_secs
                        >= original.payload.activation.activated_at_epoch_secs
                    && supersedes.committed_activation_digest
                        == activation_digests
                            .get(&supersedes.committed_sequence)
                            .cloned(),
                "supersession does not bind its exact pending intent and committed predecessor"
            );
            if let Some(previous) = &original.payload.supersedes {
                anyhow::ensure!(
                    supersedes.committed_sequence == previous.committed_sequence
                        && supersedes.committed_activation_digest
                            == previous.committed_activation_digest,
                    "supersession changed the committed predecessor of its pending chain"
                );
            } else {
                anyhow::ensure!(
                    supersedes.committed_sequence + 1 == supersedes.superseded_sequence,
                    "supersession does not start at the first uncommitted intent"
                );
            }
            anyhow::ensure!(
                superseded_by
                    .insert(
                        supersedes.superseded_sequence,
                        transaction.activation.sequence
                    )
                    .is_none(),
                "an activation attempt has conflicting supersession authorities"
            );
        }
        anyhow::ensure!(
            !superseded_by.contains_key(&committed_sequence),
            "activation pointer names a superseded attempt"
        );
        for record in &transactions {
            if let Some(supersedes) = &record.payload.supersedes {
                anyhow::ensure!(
                    !superseded_by.contains_key(&supersedes.committed_sequence),
                    "supersession anchor is itself a canceled attempt"
                );
            }
        }

        let latest_sequence = conceptual.keys().next_back().copied().unwrap_or(0);
        for sequence in committed_sequence + 1..=latest_sequence {
            let record = by_sequence
                .get(&sequence)
                .context("uncommitted history has no authenticated activation intent")?;
            if sequence > committed_sequence + 1 {
                anyhow::ensure!(
                    record
                        .payload
                        .supersedes
                        .as_ref()
                        .is_some_and(
                            |supersedes| supersedes.committed_sequence == committed_sequence
                        )
                        && superseded_by.get(&(sequence - 1)) == Some(&sequence),
                    "deployment has conflicting or nonconsecutive activation intents"
                );
            }
            if let Some(recovery) = &record.payload.recovery {
                anyhow::ensure!(
                    pointer
                        .as_ref()
                        .is_some_and(|active| active.release_id == recovery.failed_release_id),
                    "recovery intent does not identify the active failed release"
                );
            }
        }

        let raw_recoveries = self.recovery_history(authority)?;
        let mut reserved_recoveries: BTreeMap<_, _> = raw_recoveries
            .iter()
            .map(|record| (record.sequence, record.clone()))
            .collect();
        let mut recovery_owners = BTreeSet::new();
        for record in &transactions {
            if let Some(recovery) = &record.payload.recovery {
                anyhow::ensure!(
                    recovery_owners.insert(recovery.sequence),
                    "multiple intents reserve the same recovery sequence"
                );
                if let Some(existing) = reserved_recoveries.get(&recovery.sequence) {
                    anyhow::ensure!(
                        existing == recovery,
                        "partial recovery history differs from its signed intent"
                    );
                } else {
                    anyhow::ensure!(
                        record.payload.activation.sequence > committed_sequence,
                        "committed transaction is missing its retained recovery record"
                    );
                    reserved_recoveries.insert(recovery.sequence, recovery.clone());
                }
            }
        }
        anyhow::ensure!(
            reserved_recoveries
                .keys()
                .enumerate()
                .all(|(index, sequence)| *sequence == index as u64 + 1),
            "recovery reservations contain a sequence gap"
        );
        let all_activations: Vec<_> = conceptual.values().cloned().collect();
        let all_recoveries: Vec<_> = reserved_recoveries.values().cloned().collect();
        // This includes canceled reservations: their crash nonces and sequence
        // numbers must never be recycled into a later recovery outcome.
        validate_recovery_history(&all_activations, &all_recoveries)?;
        let consumed_crash_nonces = all_recoveries
            .iter()
            .map(|record| record.crash.session_nonce.clone())
            .collect();
        let recovery_high_water = reserved_recoveries.keys().next_back().copied().unwrap_or(0);
        let recoveries = all_recoveries
            .into_iter()
            .filter(|recovery| {
                recovery.activation_sequence.is_none_or(|sequence| {
                    sequence <= committed_sequence && !superseded_by.contains_key(&sequence)
                })
            })
            .collect();
        let committed = all_activations
            .into_iter()
            .filter(|activation| {
                activation.sequence <= committed_sequence
                    && !superseded_by.contains_key(&activation.sequence)
            })
            .collect();
        let superseded = superseded_by
            .iter()
            .map(|(sequence, successor)| {
                let original = by_sequence
                    .get(sequence)
                    .expect("validated supersession original");
                let replacement = by_sequence
                    .get(successor)
                    .expect("validated supersession successor");
                SupersededActivation {
                    transaction_digest: original.digest.clone(),
                    activation: original.payload.activation.clone(),
                    planned_recovery: original.payload.recovery.clone(),
                    superseded_by_sequence: *successor,
                    superseded_by_operator_id: replacement
                        .payload
                        .activation
                        .operator_id
                        .clone()
                        .expect("operator supersession"),
                    reason: replacement
                        .payload
                        .supersedes
                        .as_ref()
                        .expect("supersession authority")
                        .reason
                        .clone(),
                }
            })
            .collect();
        let pending_record = (latest_sequence > committed_sequence).then(|| {
            by_sequence
                .get(&latest_sequence)
                .expect("validated pending intent")
        });
        let pending = pending_record.map(|record| record.payload.clone());
        let pending_digest = pending_record.map(|record| record.digest.clone());
        Ok(ActivationState {
            committed,
            recoveries,
            pending,
            pending_digest,
            superseded,
            transactions,
            recovery_high_water,
            consumed_crash_nonces,
        })
    }

    /// Inspect committed activations and a pending signed operation without
    /// writing state or treating the operation as a current execution grant.
    pub fn activation_status(
        &self,
        authority: &DeploymentAuthority,
    ) -> Result<DeploymentActivationStatus> {
        let state = self.activation_state(authority)?;
        Ok(DeploymentActivationStatus {
            activations: state.committed,
            pending: state.pending.map(|transaction| PendingActivation {
                transaction_digest: state
                    .pending_digest
                    .expect("authenticated pending identity"),
                activation: transaction.activation,
                planned_recovery: transaction.recovery,
            }),
            superseded: state.superseded,
        })
    }

    /// Verified activation chain, oldest first. The pointer must equal the
    /// newest link and every rollback must have its matching recovery record.
    /// A durable but unfinished intent never authorizes execution by itself.
    pub fn activations(&self, authority: &DeploymentAuthority) -> Result<Vec<ActivationRecord>> {
        let state = self.activation_state(authority)?;
        anyhow::ensure!(
            state.pending.is_none(),
            "deployment `{}` has a pending signed activation transaction; use deploy reconcile",
            self.name
        );
        Ok(state.committed)
    }

    /// The release the pointer names, if any.
    pub fn active(&self, authority: &DeploymentAuthority) -> Result<Option<ActivationRecord>> {
        Ok(self.activations(authority)?.pop())
    }

    /// Capture a continuation restriction while this store's lock still
    /// serializes the already authenticated activation and its child spawn.
    /// The selected release is bound to the child's existing config/approval
    /// pins; no private deployment signing material enters the restriction.
    pub fn capture_activation_restriction(
        &self,
        lock: &DeploymentLock,
        authority: &DeploymentAuthority,
        activation: &ActivationRecord,
    ) -> Result<ActivationRestriction> {
        self.require_lock(lock)?;
        anyhow::ensure!(
            self.active(authority)?.as_ref() == Some(activation),
            "deployment activation changed before its continuation restriction"
        );
        #[cfg(not(unix))]
        anyhow::bail!("deployment activation retirement requires Unix directory handles");
        #[cfg(unix)]
        {
            use rustix::fs::{Mode, OFlags, openat};
            let release = self.release(authority, &activation.release_id)?;
            let store_root = if self.root.is_absolute() {
                self.root.clone()
            } else {
                std::env::current_dir()?.join(&self.root)
            };
            let (directory, directories) = open_restricted_directory(&store_root)?;
            let held_identity = restricted_directory_identity(&lock._file.metadata()?);
            let check_lock = || -> Result<()> {
                let file = File::from(openat(
                    &directory,
                    "deployment.lock",
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )?);
                let metadata = file.metadata()?;
                anyhow::ensure!(
                    metadata.is_file() && restricted_directory_identity(&metadata) == held_identity,
                    "deployment restriction is not protected by the held store lock"
                );
                Ok(())
            };
            check_lock()?;
            let bytes = read_restricted_pointer(&directory)?;
            let record: SignedRecord<ActivationRecord> =
                serde_json::from_slice(&bytes).context("invalid admitted deployment pointer")?;
            authority.open(&record, "admitted deployment pointer")?;
            anyhow::ensure!(
                &record.payload == activation,
                "deployment pointer differs from the authenticated activation"
            );
            let restriction = ActivationRestriction {
                schema_version: ACTIVATION_RESTRICTION_SCHEMA.into(),
                store_root,
                deployment: self.name.clone(),
                activation_sequence: activation.sequence,
                release_id: activation.release_id.clone(),
                release_dir: release.release_dir,
                config_sha256: release.config_sha256,
                approval_sha256: release.approval.admission_sha256()?,
                activation_digest: record_digest(&record)?,
                pointer_sha256: restriction_bytes_hash(&bytes),
                signer_public_key_hex: authority.public_key_hex(),
                directories,
                activations: inspect_restricted_history(
                    &directory,
                    "activations",
                    activation.sequence,
                )?
                .context("admitted activation has no retained history")?,
                transactions: inspect_restricted_history(
                    &directory,
                    "transactions",
                    activation.sequence,
                )?,
            };
            restriction.enforce()?;
            // Authenticate the complete chain again between two identical
            // filesystem observations. A record modified after the first
            // active() call must not become the new captured baseline.
            anyhow::ensure!(
                self.active(authority)?.as_ref() == Some(activation),
                "deployment activation changed while its restriction was captured"
            );
            restriction.enforce()?;
            check_lock()?;
            Ok(restriction)
        }
    }

    /// Append an activation and move the pointer to it.
    #[allow(clippy::too_many_arguments)]
    pub fn activate(
        &self,
        lock: &DeploymentLock,
        authority: &DeploymentAuthority,
        release_id: &str,
        reason: ActivationReason,
        operator_id: Option<&str>,
        recovery_sequence: Option<u64>,
        now_secs: u64,
    ) -> Result<ActivationRecord> {
        self.require_lock(lock)?;
        anyhow::ensure!(
            reason == ActivationReason::Operator && recovery_sequence.is_none(),
            "rollback activation requires a complete recovery transaction"
        );
        let activation = self.prepare_activation(
            authority,
            release_id,
            reason,
            operator_id,
            recovery_sequence,
            now_secs,
        )?;
        let transaction = ActivationTransaction {
            schema_version: TRANSACTION_SCHEMA.to_string(),
            deployment: self.name.clone(),
            activation: activation.clone(),
            recovery: None,
            recovery_policy: None,
            supersedes: None,
        };
        self.commit_transaction(authority, &transaction)?;
        Ok(activation)
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_activation(
        &self,
        authority: &DeploymentAuthority,
        release_id: &str,
        reason: ActivationReason,
        operator_id: Option<&str>,
        recovery_sequence: Option<u64>,
        now_secs: u64,
    ) -> Result<ActivationRecord> {
        self.enforce_release_execution_health(authority, release_id)?;
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
            supersedes_transaction_digest: None,
        };
        validate_activation_shape(&activation)?;
        Ok(activation)
    }

    fn commit_transaction(
        &self,
        authority: &DeploymentAuthority,
        transaction: &ActivationTransaction,
    ) -> Result<()> {
        write_new(
            &self.transaction_path(transaction.activation.sequence),
            &authority.seal(transaction.clone())?,
        )?;
        deployment_stop_after("intent");
        self.finish_transaction(authority, transaction)
    }

    fn finish_transaction(
        &self,
        authority: &DeploymentAuthority,
        transaction: &ActivationTransaction,
    ) -> Result<()> {
        let state = self.activation_state(authority)?;
        anyhow::ensure!(
            state.pending.as_ref() == Some(transaction),
            "activation transaction is no longer the pending operation"
        );
        let committed_sequence = state.committed.last().map_or(0, |record| record.sequence);
        for record in state
            .transactions
            .iter()
            .filter(|record| record.payload.activation.sequence > committed_sequence)
        {
            let attempt = &record.payload;
            let latest = attempt.activation.sequence == transaction.activation.sequence;
            // Missing predecessor records are materialized from their original
            // signed plans only after cancellation authority is durable. They
            // remain superseded audit evidence, never committed recovery outcomes.
            write_identical_or_new(
                &self.activation_path(attempt.activation.sequence),
                &authority.seal(attempt.activation.clone())?,
            )?;
            deployment_stop_after(if latest {
                "history"
            } else {
                "superseded_history"
            });
            if let Some(recovery) = &attempt.recovery {
                write_identical_or_new(
                    &self.recovery_path(recovery.sequence),
                    &authority.seal(recovery.clone())?,
                )?;
                deployment_stop_after(if latest {
                    "recovery"
                } else {
                    "superseded_recovery"
                });
            }
        }
        // The pointer is the commit point. Readers also authenticate every
        // linked record; neither a dangling recovery nor an intent is a run grant.
        write_replace(
            &self.pointer_path(),
            &authority.seal(transaction.activation.clone())?,
        )
    }

    /// Finish one authenticated interrupted activation without starting a
    /// guest. Missing intents, divergent partial writes and changed policy
    /// remain contained. The caller must re-verify source, configuration,
    /// publisher authority and current runtime trust in `verify`.
    pub fn reconcile_pending(
        &self,
        lock: &DeploymentLock,
        authority: &DeploymentAuthority,
        now_secs: u64,
        verify: &dyn Fn(&ReleaseRecord) -> Result<()>,
    ) -> Result<Option<ActivationRecord>> {
        self.require_lock(lock)?;
        let state = self.activation_state(authority)?;
        let Some(transaction) = state.pending else {
            return Ok(None);
        };
        let activation = &transaction.activation;
        anyhow::ensure!(
            activation.activated_at_epoch_secs <= now_secs,
            "activation intent is dated in the future"
        );
        let release = self.release(authority, &activation.release_id)?;
        self.enforce_release_execution_health(authority, &release.release_id)?;
        anyhow::ensure!(
            release.installed_at_epoch_secs <= now_secs,
            "release admission is dated in the future"
        );
        if let (Some(recovery), Some(policy)) =
            (&transaction.recovery, &transaction.recovery_policy)
        {
            anyhow::ensure!(
                self.policy(authority)? == *policy && policy.set_at_epoch_secs <= now_secs,
                "recovery policy changed after the signed activation intent"
            );
            anyhow::ensure!(
                state
                    .committed
                    .last()
                    .is_some_and(|active| active.release_id == recovery.failed_release_id)
                    && recovery.crash.observed_at_epoch_secs <= now_secs
                    && !state.recoveries.iter().any(
                        |previous| previous.crash.session_nonce == recovery.crash.session_nonce
                    ),
                "recovery intent does not identify a fresh crash of the active release"
            );
            let failed_health = self.health(authority, &recovery.failed_release_id)?;
            anyhow::ensure!(
                !failed_health.has_indeterminate_native_effects(),
                "recovery intent now has indeterminate native effects"
            );
            anyhow::ensure!(
                failed_health.events.iter().any(|event| matches!(event, HealthEvent::CrashLoop { evidence } if evidence == &recovery.crash)),
                "recovery intent lacks its recorded crash-loop evidence"
            );
            let health = self.health(authority, &release.release_id)?;
            anyhow::ensure!(
                state
                    .committed
                    .iter()
                    .any(|previous| previous.release_id == release.release_id)
                    && !health.crash_looped()
                    && !health.has_indeterminate_native_effects()
                    && health
                        .last_healthy_at()
                        .is_some_and(|observed| observed <= now_secs),
                "recovery target no longer has eligible known-good readiness"
            );
        }
        verify(&release)
            .context("pending activation target failed current release verification")?;
        self.finish_transaction(authority, &transaction)?;
        self.activations(authority)?;
        Ok(Some(activation.clone()))
    }

    /// Explicitly replace a pending operation under new operator authority.
    /// The expected signed-intent digest is a compare-and-swap guard: retries
    /// can complete the exact replacement, but cannot revive or overwrite it.
    /// This operation never starts a guest or inherits automatic restart policy.
    #[allow(clippy::too_many_arguments)]
    pub fn supersede_pending(
        &self,
        lock: &DeploymentLock,
        authority: &DeploymentAuthority,
        expected_pending_digest: &str,
        release_id: &str,
        operator_id: &str,
        reason: &str,
        now_secs: u64,
        verify: &dyn Fn(&ReleaseRecord) -> Result<()>,
    ) -> Result<DeploymentSupersedeOutcome> {
        self.require_lock(lock)?;
        validate_identifier("release id", release_id)?;
        validate_operator_id(operator_id)?;
        validate_supersession_reason(reason)?;
        let state = self.activation_state(authority)?;
        let verify_target = |activation: &ActivationRecord| -> Result<()> {
            let release = self.release(authority, &activation.release_id)?;
            self.enforce_release_execution_health(authority, &release.release_id)?;
            anyhow::ensure!(
                release.installed_at_epoch_secs <= now_secs
                    && activation.activated_at_epoch_secs <= now_secs,
                "supersession target admission or operation is dated in the future"
            );
            verify(&release).context("supersession target failed current release verification")
        };

        if let Some(existing) = state.transactions.iter().find(|record| {
            record
                .payload
                .supersedes
                .as_ref()
                .is_some_and(|supersedes| {
                    supersedes.superseded_transaction_digest == expected_pending_digest
                })
        }) {
            let transaction = &existing.payload;
            let supersedes = transaction
                .supersedes
                .as_ref()
                .expect("matched supersession");
            anyhow::ensure!(
                transaction.activation.release_id == release_id
                    && transaction.activation.operator_id.as_deref() == Some(operator_id)
                    && supersedes.reason == reason,
                "pending identity already has a different signed supersession"
            );
            let already_committed =
                state.pending.is_none() && state.committed.last() == Some(&transaction.activation);
            anyhow::ensure!(
                already_committed
                    || state.pending_digest.as_deref() == Some(existing.digest.as_str()),
                "supersession request is stale; a later operation owns the deployment"
            );
            verify_target(&transaction.activation)?;
            if !already_committed {
                self.finish_transaction(authority, transaction)?;
                self.activations(authority)?;
            }
            return Ok(DeploymentSupersedeOutcome {
                activation: transaction.activation.clone(),
                already_committed,
                superseded_transaction_digest: expected_pending_digest.to_string(),
            });
        }

        anyhow::ensure!(
            state.pending_digest.as_deref() == Some(expected_pending_digest),
            "pending activation identity changed; inspect status before superseding"
        );
        let original = state
            .pending
            .as_ref()
            .context("deployment has no pending activation")?;
        let sequence = original
            .activation
            .sequence
            .checked_add(1)
            .filter(|sequence| *sequence <= MAX_ACTIVATIONS)
            .context("supersession exceeds the deployment activation bound")?;
        anyhow::ensure!(
            original.activation.activated_at_epoch_secs <= now_secs,
            "pending activation is dated in the future"
        );
        let predecessor: SignedRecord<ActivationRecord> = if self
            .activation_path(original.activation.sequence)
            .try_exists()?
        {
            read_json(&self.activation_path(original.activation.sequence))?
        } else {
            authority.seal(original.activation.clone())?
        };
        let committed_sequence = state.committed.last().map_or(0, |record| record.sequence);
        let committed_activation_digest = if committed_sequence == 0 {
            None
        } else {
            let record: SignedRecord<ActivationRecord> =
                read_json(&self.activation_path(committed_sequence))?;
            Some(record_digest(&record)?)
        };
        let activation = ActivationRecord {
            schema_version: SUPERSESSION_ACTIVATION_SCHEMA.into(),
            deployment: self.name.clone(),
            sequence,
            release_id: release_id.to_string(),
            reason: ActivationReason::Operator,
            operator_id: Some(operator_id.to_string()),
            recovery_sequence: None,
            previous_activation_digest: Some(record_digest(&predecessor)?),
            activated_at_epoch_secs: now_secs,
            supersedes_transaction_digest: Some(expected_pending_digest.to_string()),
        };
        verify_target(&activation)?;
        let transaction = ActivationTransaction {
            schema_version: SUPERSESSION_TRANSACTION_SCHEMA.into(),
            deployment: self.name.clone(),
            activation: activation.clone(),
            recovery: None,
            recovery_policy: None,
            supersedes: Some(SupersessionAuthority {
                superseded_sequence: original.activation.sequence,
                superseded_transaction_digest: expected_pending_digest.to_string(),
                committed_sequence,
                committed_activation_digest,
                reason: reason.to_string(),
            }),
        };
        self.commit_transaction(authority, &transaction)?;
        self.activations(authority)?;
        Ok(DeploymentSupersedeOutcome {
            activation,
            already_committed: false,
            superseded_transaction_digest: expected_pending_digest.to_string(),
        })
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

    /// Refuse fresh execution or activation of an immutable release whose
    /// authenticated history records a crash loop or unresolved native effects.
    /// The unsigned local safe-mode controller cannot clear these restrictions.
    /// Recovery selects a separately admitted release; retained failure evidence
    /// is never erased or converted into readiness by a later healthy report.
    pub fn enforce_release_execution_health(
        &self,
        authority: &DeploymentAuthority,
        release_id: &str,
    ) -> Result<()> {
        self.release(authority, release_id)?;
        let health = self.health(authority, release_id)?;
        anyhow::ensure!(
            !health.crash_looped(),
            "release `{release_id}` is contained by authenticated crash-loop history; admit and activate a repaired release with a new release ID"
        );
        anyhow::ensure!(
            !health.has_indeterminate_native_effects(),
            "release `{release_id}` retains authenticated indeterminate native effects; resolve the effects and admit a repaired release with a new release ID"
        );
        Ok(())
    }

    pub fn record_health(
        &self,
        lock: &DeploymentLock,
        authority: &DeploymentAuthority,
        release_id: &str,
        event: HealthEvent,
    ) -> Result<ReleaseHealth> {
        self.require_lock(lock)?;
        let release = self.release(authority, release_id)?;
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
        if let HealthEvent::NativePanic { evidence } = &event {
            let nonce = uuid::Uuid::parse_str(&evidence.session_nonce)
                .context("native panic session identity is not a UUID")?;
            anyhow::ensure!(
                nonce.to_string() == evidence.session_nonce
                    && !nonce.is_nil()
                    && Path::new(&evidence.entrypoint)
                        == release.release_dir.join(&release.entrypoint),
                "native panic is not bound to the admitted release entrypoint"
            );
            for existing in &health.events {
                if let HealthEvent::NativePanic { evidence: seen } = existing {
                    if seen.session_nonce == evidence.session_nonce {
                        anyhow::ensure!(
                            seen == evidence,
                            "native panic session nonce was replayed with different evidence"
                        );
                        return Ok(health);
                    }
                    anyhow::ensure!(
                        seen.observed_at_epoch_secs <= evidence.observed_at_epoch_secs,
                        "native panic observation predates retained history; refusing clock rollback"
                    );
                }
            }
        }
        if let HealthEvent::CrashLoop { evidence } = &event {
            anyhow::ensure!(
                !evidence.session_nonce.is_empty()
                    && evidence.session_nonce.len() <= MAX_REASON_BYTES,
                "crash-loop session nonce is invalid"
            );
            for existing in &health.events {
                if let HealthEvent::CrashLoop { evidence: seen } = existing
                    && seen.session_nonce == evidence.session_nonce
                {
                    anyhow::ensure!(
                        seen == evidence,
                        "crash-loop session nonce was replayed with different evidence"
                    );
                    return Ok(health);
                }
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
                    "release `{release_id}` retains {MAX_HEALTH_EVENTS} native panic or crash-loop marks; none may be evicted"
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

    fn recovery_history(&self, authority: &DeploymentAuthority) -> Result<Vec<RecoveryRecord>> {
        let mut recoveries = Vec::new();
        for sequence in record_sequences(&self.root.join("recoveries"), MAX_RECOVERIES, true)? {
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
        }
        Ok(recoveries)
    }

    /// Verified committed recoveries, oldest first. An interrupted rollback
    /// receipt remains visible only as a pending plan until its pointer commits.
    pub fn recoveries(&self, authority: &DeploymentAuthority) -> Result<Vec<RecoveryRecord>> {
        Ok(self.activation_state(authority)?.recoveries)
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
            if health.has_indeterminate_native_effects() {
                refusals.push(refuse(
                    "release retains indeterminate native effects".to_string(),
                ));
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
        self.require_lock(lock)?;
        anyhow::ensure!(
            self.policy(authority)? == *policy,
            "recovery policy is not the current authenticated deployment policy"
        );
        let indeterminate_effects = self
            .health(authority, failed_release_id)?
            .has_indeterminate_native_effects();
        anyhow::ensure!(
            self.active(authority)?
                .as_ref()
                .is_some_and(|active| active.release_id == failed_release_id),
            "crashed release is no longer the active deployment"
        );
        anyhow::ensure!(
            crash.threshold > 0
                && crash.crashes_in_window >= crash.threshold
                && crash.observed_at_epoch_secs <= now_secs
                && policy.set_at_epoch_secs <= now_secs,
            "crash-loop evidence or recovery policy is invalid or future-dated"
        );
        let prior_state = self.activation_state(authority)?;
        anyhow::ensure!(
            !prior_state
                .consumed_crash_nonces
                .contains(&crash.session_nonce),
            "crash-loop session nonce already has a recovery outcome"
        );
        self.record_health(
            lock,
            authority,
            failed_release_id,
            HealthEvent::CrashLoop {
                evidence: crash.clone(),
            },
        )?;
        let sequence = prior_state.recovery_high_water + 1;
        anyhow::ensure!(
            sequence <= MAX_RECOVERIES,
            "deployment `{}` exceeds {MAX_RECOVERIES} recoveries",
            self.name
        );
        let (outcome, selected_release_id, activation, candidate_refusals) =
            if indeterminate_effects {
                (
                    RecoveryOutcome::ContainedEffectsIndeterminate,
                    None,
                    None,
                    Vec::new(),
                )
            } else {
                match policy.on_crash_loop {
                    CrashLoopAction::Contain => {
                        (RecoveryOutcome::Contained, None, None, Vec::new())
                    }
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
                                let activation = self.prepare_activation(
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
                                    Some(activation),
                                    selection.refusals,
                                )
                            }
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
            activation_sequence: activation.as_ref().map(|record| record.sequence),
            candidate_refusals,
            recorded_at_epoch_secs: now_secs,
        };
        if let Some(activation) = activation {
            self.commit_transaction(
                authority,
                &ActivationTransaction {
                    schema_version: TRANSACTION_SCHEMA.to_string(),
                    deployment: self.name.clone(),
                    activation,
                    recovery: Some(recovery.clone()),
                    recovery_policy: Some(policy.clone()),
                    supersedes: None,
                },
            )?;
        } else {
            write_new(
                &self.recovery_path(sequence),
                &authority.seal(recovery.clone())?,
            )?;
        }
        Ok(recovery)
    }
}

fn validate_activation_shape(activation: &ActivationRecord) -> Result<()> {
    anyhow::ensure!(
        (activation.schema_version == ACTIVATION_SCHEMA
            && activation.supersedes_transaction_digest.is_none())
            || (activation.schema_version == SUPERSESSION_ACTIVATION_SCHEMA
                && activation.supersedes_transaction_digest.is_some()
                && activation.reason == ActivationReason::Operator),
        "activation schema does not authenticate its supersession semantics"
    );
    validate_identifier("release id", &activation.release_id)?;
    anyhow::ensure!(
        (1..=MAX_ACTIVATIONS).contains(&activation.sequence),
        "activation sequence is out of bounds"
    );
    match activation.reason {
        ActivationReason::Operator => {
            validate_operator_id(
                activation
                    .operator_id
                    .as_deref()
                    .context("operator activation lacks an operator")?,
            )?;
            anyhow::ensure!(
                activation.recovery_sequence.is_none(),
                "operator activation names a recovery"
            );
        }
        ActivationReason::CrashLoopRollback => anyhow::ensure!(
            activation.operator_id.is_none()
                && activation
                    .recovery_sequence
                    .is_some_and(|sequence| (1..=MAX_RECOVERIES).contains(&sequence)),
            "rollback activation lacks a valid recovery identity"
        ),
    }
    Ok(())
}

fn validate_recovery_link(activation: &ActivationRecord, recovery: &RecoveryRecord) -> Result<()> {
    anyhow::ensure!(
        activation.reason == ActivationReason::CrashLoopRollback
            && activation.recovery_sequence == Some(recovery.sequence)
            && recovery.schema_version == RECOVERY_SCHEMA
            && recovery.deployment == activation.deployment
            && recovery.outcome == RecoveryOutcome::RolledBack
            && recovery.on_crash_loop == CrashLoopAction::Rollback
            && recovery.selected_release_id.as_deref() == Some(activation.release_id.as_str())
            && recovery.failed_release_id != activation.release_id
            && recovery.activation_sequence == Some(activation.sequence)
            && recovery.recorded_at_epoch_secs == activation.activated_at_epoch_secs,
        "rollback activation and recovery do not authenticate the same transition"
    );
    Ok(())
}

fn validate_recovery_history(
    chain: &[ActivationRecord],
    recoveries: &[RecoveryRecord],
) -> Result<()> {
    for activation in chain {
        if let Some(sequence) = activation.recovery_sequence {
            let recovery = recoveries
                .iter()
                .find(|record| record.sequence == sequence)
                .context("rollback activation has no committed recovery record")?;
            validate_recovery_link(activation, recovery)?;
        }
    }
    let mut sessions = BTreeSet::new();
    for recovery in recoveries {
        anyhow::ensure!(
            sessions.insert(recovery.crash.session_nonce.as_str()),
            "recovery history reuses a crash session nonce"
        );
        if recovery.outcome == RecoveryOutcome::RolledBack {
            let activation = chain
                .iter()
                .find(|activation| Some(activation.sequence) == recovery.activation_sequence)
                .context("rollback recovery has no committed activation")?;
            validate_recovery_link(activation, recovery)?;
        } else {
            anyhow::ensure!(
                recovery.selected_release_id.is_none() && recovery.activation_sequence.is_none(),
                "contained recovery cannot name an activated release"
            );
        }
    }
    Ok(())
}

/// Inspect the whole bounded directory so a missing middle record cannot hide
/// later signed history. Temporary files from interrupted writes are retained.
fn record_sequences(directory: &Path, maximum: u64, contiguous: bool) -> Result<Vec<u64>> {
    if !directory.try_exists()? {
        return Ok(Vec::new());
    }
    let mut sequences = Vec::new();
    for (index, entry) in fs::read_dir(directory)?.enumerate() {
        anyhow::ensure!(
            (index as u64) < maximum * 4,
            "deployment history directory exceeds its entry bound"
        );
        let name = entry?.file_name();
        let name = name
            .to_str()
            .context("deployment history filename is not UTF-8")?;
        if name.starts_with('.') && name.ends_with(".tmp") {
            continue;
        }
        let sequence = name
            .strip_suffix(".json")
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|sequence| (1..=maximum).contains(sequence))
            .context("deployment history contains an invalid sequence filename")?;
        anyhow::ensure!(
            name == format!("{sequence:010}.json"),
            "deployment history filename is not canonical"
        );
        sequences.push(sequence);
    }
    sequences.sort_unstable();
    if contiguous {
        anyhow::ensure!(
            sequences
                .iter()
                .enumerate()
                .all(|(index, sequence)| *sequence == index as u64 + 1),
            "deployment history contains a sequence gap"
        );
    }
    Ok(sequences)
}

// Deterministic real-process interruption drills are never compiled into
// default/release builds. No sleep, mocked write, or forged receipt is needed.
fn deployment_stop_after(stage: &str) {
    #[cfg(feature = "test-support")]
    if std::env::var("FRANKEN_NODE_TEST_DEPLOYMENT_STOP_AFTER").as_deref() == Ok(stage) {
        std::process::exit(86);
    }
    #[cfg(not(feature = "test-support"))]
    let _ = stage;
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

fn write_identical_or_new<T: Serialize + DeserializeOwned + PartialEq>(
    path: &Path,
    value: &T,
) -> Result<()> {
    if path.try_exists()? {
        let existing: T = read_json(path)?;
        anyhow::ensure!(
            &existing == value,
            "partial deployment record conflicts with its signed transaction"
        );
        Ok(())
    } else {
        write_new(path, value)
    }
}

/// Persist newly created directories and the parent entries that name them.
/// Syncing only a record's immediate parent can lose the entire new history
/// directory after power loss even when its activation pointer was flushed.
fn create_durable_directory(path: &Path) -> Result<()> {
    let mut missing = Vec::new();
    let mut current = path.to_path_buf();
    while !current.try_exists()? {
        missing.push(current.clone());
        let parent = current
            .parent()
            .context("deployment directory has no existing ancestor")?;
        current = if parent.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            parent.to_path_buf()
        };
    }
    fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
    #[cfg(unix)]
    for directory in missing.iter().rev() {
        File::open(directory)?.sync_all()?;
        let parent = directory
            .parent()
            .context("deployment directory has no parent")?;
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Durably replace `path` (temp file, fsync, rename, directory fsync).
fn write_replace<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .context("deployment record path has no parent")?;
    create_durable_directory(parent)?;
    let bytes = serde_json::to_vec_pretty(value)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_RECORD_BYTES,
        "deployment record exceeds {MAX_RECORD_BYTES} bytes"
    );
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

    fn native_panic(release_id: &str, nonce: u128, at: u64, no_effects: bool) -> HealthEvent {
        HealthEvent::NativePanic {
            evidence: NativePanicEvidence {
                session_nonce: uuid::Uuid::from_u128(nonce).to_string(),
                entrypoint: format!("/releases/{release_id}/app.js"),
                observed_at_epoch_secs: at,
                no_admitted_host_effects: no_effects,
            },
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

    #[cfg(unix)]
    fn restriction_fixture() -> (Fixture, ActivationRecord, ActivationRestriction) {
        let mut f = fixture();
        // The CLI admits an already canonical operator root. Preserve that
        // contract on hosts whose temporary directory has a symlinked ancestor.
        f.store = DeploymentStore::open(&f._dir.path().canonicalize().unwrap(), "app").unwrap();
        let (active, restriction) = {
            let lock = f.store.lock().unwrap();
            f.store
                .install_release(&lock, &f.authority, test_release(&f.store, "v1"))
                .unwrap();
            let active = f
                .store
                .activate(
                    &lock,
                    &f.authority,
                    "v1",
                    ActivationReason::Operator,
                    Some("ops"),
                    None,
                    20,
                )
                .unwrap();
            let restriction = f
                .store
                .capture_activation_restriction(&lock, &f.authority, &active)
                .unwrap();
            (active, restriction)
        };
        (f, active, restriction)
    }

    #[cfg(unix)]
    #[test]
    fn activation_restriction_round_trip_preserves_unchanged_admission_without_secrets() {
        let (f, active, restriction) = restriction_fixture();
        restriction.enforce().unwrap();
        let bytes = serde_json::to_vec(&restriction).unwrap();
        assert!(bytes.len() < 64 * 1024);
        assert!(!String::from_utf8_lossy(&bytes).contains(&"07".repeat(32)));
        let decoded: ActivationRestriction = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, restriction);
        assert_eq!(decoded.store_root(), f.store.root());
        assert_eq!(decoded.deployment(), "app");
        assert_eq!(decoded.activation_sequence(), active.sequence);
        assert_eq!(decoded.release_id(), active.release_id);
        let pointer_bytes = fs::read(f.store.pointer_path()).unwrap();
        assert_eq!(
            decoded.pointer_sha256,
            restriction_bytes_hash(&pointer_bytes)
        );
        let pointer: SignedRecord<ActivationRecord> =
            serde_json::from_slice(&pointer_bytes).unwrap();
        assert_eq!(decoded.activation_digest, record_digest(&pointer).unwrap());
        assert_eq!(decoded.signer_public_key_hex, f.authority.public_key_hex());
        // Replacement with the exact retained bytes does not change activation
        // identity. Directory identity is pinned; active.json inode is not.
        fs::rename(
            f.store.pointer_path(),
            f.store.root().join("retained-active.json"),
        )
        .unwrap();
        fs::write(f.store.pointer_path(), &pointer_bytes).unwrap();
        decoded.enforce().unwrap();
        let lock = f.store.lock().unwrap();
        f.store
            .record_health(&lock, &f.authority, "v1", healthy("healthy-run", 30))
            .unwrap();
        f.store
            .set_policy(&lock, &f.authority, rollback_policy(&f.store))
            .unwrap();
        decoded.enforce().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn activation_restriction_retires_same_release_reactivation_even_after_pointer_restore() {
        let (f, active, restriction) = restriction_fixture();
        let old_pointer = fs::read(f.store.pointer_path()).unwrap();
        let lock = f.store.lock().unwrap();
        let successor = f
            .store
            .activate(
                &lock,
                &f.authority,
                "v1",
                ActivationReason::Operator,
                Some("ops"),
                None,
                30,
            )
            .unwrap();
        assert_eq!(successor.release_id, active.release_id);
        assert_eq!(successor.sequence, active.sequence + 1);
        assert_eq!(
            successor.previous_activation_digest.as_deref(),
            Some(restriction.activation_digest.as_str())
        );
        assert!(restriction.enforce().is_err());
        let next = f
            .store
            .capture_activation_restriction(&lock, &f.authority, &successor)
            .unwrap();
        next.enforce().unwrap();
        fs::write(f.store.pointer_path(), old_pointer).unwrap();
        assert!(
            restriction.enforce().is_err(),
            "retained successor history cannot be hidden by old pointer bytes"
        );
        assert!(
            next.enforce().is_err(),
            "the successor cannot accept the restored predecessor"
        );
    }

    #[cfg(unix)]
    #[test]
    fn activation_restriction_retires_on_intent_before_pointer_commit() {
        let (f, active, restriction) = restriction_fixture();
        let old_pointer = fs::read(f.store.pointer_path()).unwrap();
        let lock = f.store.lock().unwrap();
        let pending = pending_operator(&f, &lock);
        assert_eq!(pending.activation.sequence, active.sequence + 1);
        retain_intent(&f, &pending);
        assert_eq!(fs::read(f.store.pointer_path()).unwrap(), old_pointer);
        assert!(restriction.enforce().is_err());
        assert!(f.store.active(&f.authority).is_err());
        assert!(
            f.store
                .capture_activation_restriction(&lock, &f.authority, &active)
                .is_err()
        );
        // The live observer latches this first refusal. The restriction does
        // not claim to detect an erased intent between periodic observations.
    }

    #[cfg(unix)]
    #[test]
    fn activation_restriction_refuses_missing_malformed_and_foreign_pointers() {
        for change in 0..3 {
            let (f, active, restriction) = restriction_fixture();
            match change {
                0 => fs::rename(
                    f.store.pointer_path(),
                    f.store.root().join("retained-pointer.json"),
                )
                .unwrap(),
                1 => fs::write(f.store.pointer_path(), b"{ malformed").unwrap(),
                _ => {
                    let foreign = authority(9).seal(active).unwrap();
                    fs::write(
                        f.store.pointer_path(),
                        serde_json::to_vec(&foreign).unwrap(),
                    )
                    .unwrap();
                }
            }
            assert!(restriction.enforce().is_err(), "pointer mutation {change}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn activation_restriction_pins_directory_identity_and_never_follows_symlinks() {
        use std::os::unix::fs::symlink;
        for replacement_is_symlink in [false, true] {
            let (f, _, restriction) = restriction_fixture();
            let retained = f.store.root().with_file_name("retained-app");
            fs::rename(f.store.root(), &retained).unwrap();
            if replacement_is_symlink {
                symlink(&retained, f.store.root()).unwrap();
            } else {
                fs::create_dir(f.store.root()).unwrap();
                fs::copy(retained.join("active.json"), f.store.pointer_path()).unwrap();
            }
            assert!(restriction.enforce().is_err());
        }
        for component in ["active.json", "activations", "transactions"] {
            let (f, _, restriction) = restriction_fixture();
            let original = f.store.root().join(component);
            let retained = f.store.root().join(format!("retained-{component}"));
            fs::rename(&original, &retained).unwrap();
            symlink(&retained, &original).unwrap();
            assert!(
                restriction.enforce().is_err(),
                "must not follow {component}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn activation_restriction_refuses_retargeted_ancestor_and_unheld_lock() {
        use std::os::unix::fs::symlink;
        let (f, active, restriction) = restriction_fixture();
        let ancestor = f._dir.path().canonicalize().unwrap().join(".franken-node");
        let retained = f._dir.path().join("retained-state");
        fs::rename(&ancestor, &retained).unwrap();
        symlink(&retained, &ancestor).unwrap();
        assert!(restriction.enforce().is_err());
        // Capture cannot inherit a no-follow guarantee from canonicalize().
        let lock = f.store.lock().unwrap();
        assert!(
            f.store
                .capture_activation_restriction(&lock, &f.authority, &active)
                .is_err()
        );

        let (f, active, _) = restriction_fixture();
        let held = f.store.lock().unwrap();
        fs::rename(
            f.store.root().join("deployment.lock"),
            f.store.root().join("retained-lock"),
        )
        .unwrap();
        fs::write(f.store.root().join("deployment.lock"), b"").unwrap();
        assert!(
            f.store
                .capture_activation_restriction(&held, &f.authority, &active)
                .is_err()
        );
        let other = fixture();
        let other_lock = other.store.lock().unwrap();
        assert!(
            f.store
                .capture_activation_restriction(&other_lock, &f.authority, &active)
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn activation_restriction_binds_release_without_using_freshness_as_authority() {
        let (f, active, restriction) = restriction_fixture();
        let release = f.store.release(&f.authority, &active.release_id).unwrap();
        let approval = release.approval.admission_sha256().unwrap();
        restriction
            .validate_release(&release.release_dir, &release.config_sha256, &approval)
            .unwrap();
        assert!(
            restriction
                .validate_source(Path::new("/different-release"), &approval)
                .is_err()
        );
        assert!(
            restriction
                .validate_source(&release.release_dir, &format!("sha256:{}", "f".repeat(64)))
                .is_err()
        );
        assert!(
            restriction
                .validate_release(
                    &release.release_dir,
                    &format!("sha256:{}", "e".repeat(64)),
                    &approval
                )
                .is_err()
        );
        let lock = f.store.lock().unwrap();
        f.store
            .activate(
                &lock,
                &f.authority,
                "v1",
                ActivationReason::Operator,
                Some("ops"),
                None,
                30,
            )
            .unwrap();
        // Keep identity validation separate so a stale admitted child reaches
        // the dispatcher's typed activation-interrupted admission boundary.
        restriction
            .validate_release(&release.release_dir, &release.config_sha256, &approval)
            .unwrap();
        assert!(restriction.enforce().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn activation_restriction_rejects_malformed_or_incomplete_serialized_pins() {
        let (_, _, restriction) = restriction_fixture();
        let valid = serde_json::to_value(&restriction).unwrap();
        for (field, value) in [
            ("schema_version", serde_json::json!("unsupported")),
            ("activation_sequence", serde_json::json!(0)),
            (
                "activation_sequence",
                serde_json::json!(MAX_ACTIVATIONS + 1),
            ),
            ("directories", serde_json::json!([])),
            ("pointer_sha256", serde_json::json!("invalid")),
            ("store_root", serde_json::json!("/other/state")),
            ("release_dir", serde_json::json!("../release")),
            ("signer_public_key_hex", serde_json::json!("ff")),
        ] {
            let mut changed = valid.clone();
            changed[field] = value;
            let decoded: ActivationRestriction = serde_json::from_value(changed).unwrap();
            assert!(decoded.validate().is_err(), "{field}");
        }
        let mut unknown = valid;
        unknown["operator_private_key"] = serde_json::json!("not-an-allowed-field");
        assert!(serde_json::from_value::<ActivationRestriction>(unknown).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn activation_restriction_detects_same_size_in_place_history_corruption() {
        use std::os::unix::fs::MetadataExt as _;
        for history in ["activations", "transactions"] {
            let (f, _, restriction) = restriction_fixture();
            let pointer = fs::read(f.store.pointer_path()).unwrap();
            let path = f.store.root().join(history).join("0000000001.json");
            let before = fs::metadata(&path).unwrap();
            let mut bytes = fs::read(&path).unwrap();
            assert_eq!(bytes[0], b'{');
            bytes[0] = b'[';
            fs::write(&path, &bytes).unwrap();
            let after = fs::metadata(&path).unwrap();
            assert_eq!(before.ino(), after.ino(), "same record inode");
            assert_eq!(before.len(), after.len(), "same record length");
            assert_eq!(fs::read(f.store.pointer_path()).unwrap(), pointer);
            assert!(restriction.enforce().is_err(), "{history}");
            assert!(
                f.store.active(&f.authority).is_err(),
                "corrupt signed history is not an activation"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn activation_restriction_bounds_cumulative_history_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let history = directory.path().join("activations");
        fs::create_dir(&history).unwrap();
        let first = history.join("0000000001.json");
        // The reader hashes raw records; authentication belongs to capture.
        // Sparse hard links keep this boundary test's disk footprint bounded.
        File::create(&first)
            .unwrap()
            .set_len(MAX_RECORD_BYTES)
            .unwrap();
        let maximum_records = MAX_RESTRICTION_HISTORY_BYTES / MAX_RECORD_BYTES;
        for sequence in 2..=maximum_records {
            fs::hard_link(&first, history.join(format!("{sequence:010}.json"))).unwrap();
        }
        let store = File::open(directory.path()).unwrap();
        let accepted = inspect_restricted_history(&store, "activations", maximum_records)
            .unwrap()
            .unwrap();
        assert_eq!(accepted.record_count, maximum_records);
        let excessive_sequence = maximum_records + 1;
        fs::hard_link(
            &first,
            history.join(format!("{excessive_sequence:010}.json")),
        )
        .unwrap();
        let error =
            inspect_restricted_history(&store, "activations", excessive_sequence).unwrap_err();
        assert!(error.to_string().contains("exceeds its byte bound"));
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
        let policy = rollback_policy(&f.store);
        f.store
            .set_policy(&lock, &f.authority, policy.clone())
            .expect("policy");
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
        let policy = rollback_policy(&f.store);
        f.store
            .set_policy(&lock, &f.authority, policy.clone())
            .expect("policy");
        let recovery = f
            .store
            .recover_from_crash_loop(
                &lock,
                &f.authority,
                "v4",
                crash("n-1"),
                &policy,
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
    fn signed_failure_history_blocks_execution_and_activation_without_erasing_recovery() {
        let f = fixture();
        let lock = f.store.lock().unwrap();
        for id in ["v1", "v2", "v3"] {
            f.store
                .install_release(&lock, &f.authority, test_release(&f.store, id))
                .unwrap();
        }
        f.store
            .enforce_release_execution_health(&f.authority, "v1")
            .unwrap();
        f.store
            .record_health(&lock, &f.authority, "v1", native_panic("v1", 1, 20, true))
            .unwrap();
        f.store
            .enforce_release_execution_health(&f.authority, "v1")
            .expect("a single effect-free panic still permits a bounded retry");
        f.store
            .record_health(&lock, &f.authority, "v1", native_panic("v1", 2, 21, false))
            .unwrap();
        f.store
            .record_health(&lock, &f.authority, "v1", healthy("later-healthy", 22))
            .unwrap();
        f.store
            .record_health(
                &lock,
                &f.authority,
                "v2",
                HealthEvent::CrashLoop {
                    evidence: crash("retained-crash"),
                },
            )
            .unwrap();
        f.store
            .activate(
                &lock,
                &f.authority,
                "v3",
                ActivationReason::Operator,
                Some("ops"),
                None,
                101,
            )
            .expect("a separately admitted repaired release remains available");
        let pointer = fs::read(f.store.pointer_path()).unwrap();
        let journal = journal_bytes(&f.store);
        for (id, reason) in [
            ("v1", "authenticated indeterminate native effects"),
            ("v2", "authenticated crash-loop history"),
        ] {
            let health = fs::read(f.store.health_path(id)).unwrap();
            let error = f
                .store
                .enforce_release_execution_health(&f.authority, id)
                .unwrap_err();
            assert!(error.to_string().contains(reason), "{error:#}");
            let error = f
                .store
                .activate(
                    &lock,
                    &f.authority,
                    id,
                    ActivationReason::Operator,
                    Some("ops"),
                    None,
                    102,
                )
                .unwrap_err();
            assert!(error.to_string().contains(reason), "{error:#}");
            assert_eq!(fs::read(f.store.health_path(id)).unwrap(), health);
            assert_eq!(fs::read(f.store.pointer_path()).unwrap(), pointer);
            assert_eq!(journal_bytes(&f.store), journal);
        }
        f.store
            .enforce_release_execution_health(&f.authority, "v3")
            .unwrap();
        assert!(
            f.store
                .enforce_release_execution_health(&authority(8), "v3")
                .is_err()
        );
    }

    #[test]
    fn pending_operator_activation_and_supersession_recheck_signed_failure_history() {
        for indeterminate in [false, true] {
            let f = fixture();
            let lock = f.store.lock().unwrap();
            let pending = pending_operator(&f, &lock);
            retain_intent(&f, &pending);
            f.store
                .install_release(&lock, &f.authority, test_release(&f.store, "v2"))
                .unwrap();
            let event = if indeterminate {
                native_panic("v1", 1, 21, false)
            } else {
                HealthEvent::CrashLoop {
                    evidence: CrashLoopEvidence {
                        entrypoint: "/releases/v1/app.js".to_string(),
                        safe_mode_state_path:
                            "/releases/v1/.franken-node/safe-mode/state.json".to_string(),
                        ..crash("pending-target-crash")
                    },
                }
            };
            f.store
                .record_health(&lock, &f.authority, "v1", event)
                .unwrap();
            let digest = f
                .store
                .activation_status(&f.authority)
                .unwrap()
                .pending
                .unwrap()
                .transaction_digest;
            let journal = journal_bytes(&f.store);
            let verify = |_: &ReleaseRecord| -> Result<()> {
                panic!("signed containment must refuse before source verification")
            };
            let error = f
                .store
                .reconcile_pending(&lock, &f.authority, 101, &verify)
                .unwrap_err();
            assert!(error.to_string().contains("authenticated"), "{error:#}");
            let error = f
                .store
                .supersede_pending(
                    &lock,
                    &f.authority,
                    &digest,
                    "v1",
                    "ops",
                    "retry failed target",
                    101,
                    &verify,
                )
                .unwrap_err();
            assert!(error.to_string().contains("authenticated"), "{error:#}");
            assert!(!f.store.pointer_path().exists());
            assert_eq!(journal_bytes(&f.store), journal);
            let replacement = f
                .store
                .supersede_pending(
                    &lock,
                    &f.authority,
                    &digest,
                    "v2",
                    "ops",
                    "select repaired release",
                    101,
                    &|_| Ok(()),
                )
                .unwrap();
            assert_eq!(replacement.activation.release_id, "v2");
            assert_eq!(
                f.store.active(&f.authority).unwrap().unwrap().release_id,
                "v2"
            );
        }
    }

    #[test]
    fn authenticated_panic_history_deduplicates_and_ignores_unsigned_counters() {
        let f = fixture();
        let lock = f.store.lock().unwrap();
        f.store
            .install_release(&lock, &f.authority, test_release(&f.store, "v2"))
            .unwrap();
        for event in [
            native_panic("v2", 1, 20, true),
            native_panic("v2", 2, 100, true),
            native_panic("v2", 3, 101, true),
        ] {
            f.store
                .record_health(&lock, &f.authority, "v2", event)
                .unwrap();
        }
        let mut aggregate = crash("unsigned-counter");
        aggregate.crashes_in_window = 999;
        f.store
            .record_health(
                &lock,
                &f.authority,
                "v2",
                HealthEvent::CrashLoop {
                    evidence: aggregate,
                },
            )
            .unwrap();
        let nonce = uuid::Uuid::from_u128(3).to_string();
        let state = Path::new("/releases/v2/.franken-node/safe-mode/state.json");
        let before = f.store.health(&f.authority, "v2").unwrap();
        assert!(
            before
                .native_crash_loop_evidence(&nonce, 3, 60, state)
                .unwrap()
                .is_none(),
            "expired panics and aggregate crash marks cannot add authenticated launches"
        );
        assert_eq!(
            f.store
                .record_health(&lock, &f.authority, "v2", native_panic("v2", 3, 101, true))
                .unwrap(),
            before,
            "replaying the exact signed observation is idempotent"
        );
        for conflicting in [
            native_panic("v2", 3, 102, true),
            native_panic("v2", 3, 101, false),
            native_panic("v2", 4, 99, true),
            native_panic("v1", 4, 102, true),
            native_panic("v2", 0, 102, true),
        ] {
            assert!(
                f.store
                    .record_health(&lock, &f.authority, "v2", conflicting)
                    .is_err()
            );
            assert_eq!(f.store.health(&f.authority, "v2").unwrap(), before);
        }
        let health = f
            .store
            .record_health(&lock, &f.authority, "v2", native_panic("v2", 4, 102, true))
            .unwrap();
        let current = uuid::Uuid::from_u128(4).to_string();
        let crossing = health
            .native_crash_loop_evidence(&current, 3, 60, state)
            .unwrap()
            .unwrap();
        assert_eq!(crossing.crashes_in_window, 3);
        assert_eq!(crossing.observed_at_epoch_secs, 102);
        assert_eq!(crossing.session_nonce, current);
        for (threshold, window) in [
            (0, 60),
            (MAX_DEPLOYMENT_CRASH_THRESHOLD + 1, 60),
            (3, 0),
            (3, 86_401),
        ] {
            assert!(
                health
                    .native_crash_loop_evidence(&current, threshold, window, state)
                    .is_err()
            );
        }
    }

    #[test]
    fn expired_indeterminate_panic_still_blocks_signed_recovery_and_known_good_selection() {
        let f = fixture();
        let lock = f.store.lock().unwrap();
        for release in ["v1", "v2"] {
            f.store
                .install_release(&lock, &f.authority, test_release(&f.store, release))
                .unwrap();
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
            .unwrap();
        f.store
            .record_health(&lock, &f.authority, "v1", healthy("ready", 25))
            .unwrap();
        f.store
            .activate(
                &lock,
                &f.authority,
                "v2",
                ActivationReason::Operator,
                Some("ops"),
                None,
                30,
            )
            .unwrap();
        let mut policy = rollback_policy(&f.store);
        policy.restart = RestartPolicy::Automatic;
        f.store
            .set_policy(&lock, &f.authority, policy.clone())
            .unwrap();
        assert_eq!(
            f.store
                .select_known_good(&f.authority, "v2", 202, &|_| Ok(()))
                .unwrap()
                .selected
                .unwrap()
                .release_id,
            "v1"
        );
        for event in [
            native_panic("v2", 1, 40, false),
            native_panic("v2", 2, 200, true),
            native_panic("v2", 3, 201, true),
            native_panic("v2", 4, 202, true),
        ] {
            f.store
                .record_health(&lock, &f.authority, "v2", event)
                .unwrap();
        }
        let health = f.store.health(&f.authority, "v2").unwrap();
        assert!(health.has_indeterminate_native_effects());
        let crossing = health
            .native_crash_loop_evidence(
                &uuid::Uuid::from_u128(4).to_string(),
                3,
                60,
                Path::new("/releases/v2/.franken-node/safe-mode/state.json"),
            )
            .unwrap()
            .unwrap();
        assert_eq!(crossing.crashes_in_window, 3);
        let pointer = fs::read(f.store.pointer_path()).unwrap();
        let recovery = f
            .store
            .recover_from_crash_loop(&lock, &f.authority, "v2", crossing, &policy, 203, &|_| {
                Ok(())
            })
            .unwrap();
        assert_eq!(
            recovery.outcome,
            RecoveryOutcome::ContainedEffectsIndeterminate
        );
        assert!(recovery.selected_release_id.is_none());
        assert!(recovery.activation_sequence.is_none());
        assert_eq!(fs::read(f.store.pointer_path()).unwrap(), pointer);
        assert_eq!(f.store.recoveries(&f.authority).unwrap(), vec![recovery]);

        f.store
            .record_health(&lock, &f.authority, "v1", native_panic("v1", 5, 204, false))
            .unwrap();
        let selection = f
            .store
            .select_known_good(&f.authority, "v2", 205, &|_| Ok(()))
            .unwrap();
        assert!(selection.selected.is_none());
        assert!(selection.refusals.iter().any(|refusal| {
            refusal.release_id == "v1" && refusal.reason.contains("indeterminate native effects")
        }));
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

    fn pending_operator(f: &Fixture, lock: &DeploymentLock) -> ActivationTransaction {
        f.store
            .install_release(lock, &f.authority, test_release(&f.store, "v1"))
            .unwrap();
        ActivationTransaction {
            schema_version: TRANSACTION_SCHEMA.into(),
            deployment: f.store.name().into(),
            activation: f
                .store
                .prepare_activation(
                    &f.authority,
                    "v1",
                    ActivationReason::Operator,
                    Some("ops"),
                    None,
                    20,
                )
                .unwrap(),
            recovery: None,
            recovery_policy: None,
            supersedes: None,
        }
    }

    fn retain_intent(f: &Fixture, transaction: &ActivationTransaction) {
        write_new(
            &f.store.transaction_path(transaction.activation.sequence),
            &f.authority.seal(transaction.clone()).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn pending_activation_requires_current_verification_and_reconciles_idempotently() {
        for write_history in [false, true] {
            let f = fixture();
            let lock = f.store.lock().unwrap();
            let transaction = pending_operator(&f, &lock);
            retain_intent(&f, &transaction);
            let intent_bytes = fs::read(f.store.transaction_path(1)).unwrap();
            if write_history {
                write_new(
                    &f.store.activation_path(1),
                    &f.authority.seal(transaction.activation.clone()).unwrap(),
                )
                .unwrap();
            }
            assert!(f.store.active(&f.authority).is_err());
            assert!(
                f.store
                    .reconcile_pending(&lock, &f.authority, 30, &|_| anyhow::bail!(
                        "revoked release"
                    ))
                    .is_err()
            );
            assert!(!f.store.pointer_path().exists());
            let calls = std::cell::Cell::new(0);
            let repaired = f
                .store
                .reconcile_pending(&lock, &f.authority, 30, &|release| {
                    assert_eq!(release.release_id, "v1");
                    calls.set(calls.get() + 1);
                    Ok(())
                })
                .unwrap()
                .unwrap();
            assert_eq!(repaired, transaction.activation);
            assert_eq!(calls.get(), 1);
            assert_eq!(fs::read(f.store.transaction_path(1)).unwrap(), intent_bytes);
            assert_eq!(f.store.active(&f.authority).unwrap(), Some(repaired));
            assert!(
                f.store
                    .reconcile_pending(&lock, &f.authority, 30, &|_| panic!(
                        "committed transition must not be rerun"
                    ))
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn reconciliation_refuses_unlogged_conflicting_and_future_activations() {
        for case in [
            "missing_intent",
            "wrong_predecessor",
            "future",
            "conflicting_history",
        ] {
            let f = fixture();
            let lock = f.store.lock().unwrap();
            let mut transaction = pending_operator(&f, &lock);
            match case {
                "missing_intent" => {
                    write_new(
                        &f.store.activation_path(1),
                        &f.authority.seal(transaction.activation.clone()).unwrap(),
                    )
                    .unwrap();
                }
                "wrong_predecessor" => {
                    transaction.activation.previous_activation_digest =
                        Some(format!("sha256:{}", "0".repeat(64)));
                    retain_intent(&f, &transaction);
                }
                "future" => {
                    transaction.activation.activated_at_epoch_secs = 31;
                    retain_intent(&f, &transaction);
                }
                "conflicting_history" => {
                    retain_intent(&f, &transaction);
                    let mut conflicting = transaction.activation.clone();
                    conflicting.operator_id = Some("other-operator".into());
                    write_new(
                        &f.store.activation_path(1),
                        &f.authority.seal(conflicting).unwrap(),
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                f.store
                    .reconcile_pending(&lock, &f.authority, 30, &|_| Ok(()))
                    .is_err(),
                "{case}"
            );
            assert!(!f.store.pointer_path().exists(), "{case}");
        }
    }

    fn pending_rollback(f: &Fixture, lock: &DeploymentLock) -> ActivationTransaction {
        for id in ["v1", "v2"] {
            f.store
                .install_release(lock, &f.authority, test_release(&f.store, id))
                .unwrap();
            f.store
                .activate(
                    lock,
                    &f.authority,
                    id,
                    ActivationReason::Operator,
                    Some("ops"),
                    None,
                    20,
                )
                .unwrap();
        }
        f.store
            .record_health(lock, &f.authority, "v1", healthy("r-1", 30))
            .unwrap();
        let crash = crash("recovery-session");
        f.store
            .record_health(
                lock,
                &f.authority,
                "v2",
                HealthEvent::CrashLoop {
                    evidence: crash.clone(),
                },
            )
            .unwrap();
        let policy = rollback_policy(&f.store);
        f.store
            .set_policy(lock, &f.authority, policy.clone())
            .unwrap();
        let activation = f
            .store
            .prepare_activation(
                &f.authority,
                "v1",
                ActivationReason::CrashLoopRollback,
                None,
                Some(1),
                100,
            )
            .unwrap();
        let recovery = RecoveryRecord {
            schema_version: RECOVERY_SCHEMA.into(),
            deployment: f.store.name().into(),
            sequence: 1,
            failed_release_id: "v2".into(),
            crash,
            on_crash_loop: policy.on_crash_loop,
            restart: policy.restart,
            outcome: RecoveryOutcome::RolledBack,
            selected_release_id: Some("v1".into()),
            activation_sequence: Some(3),
            candidate_refusals: Vec::new(),
            recorded_at_epoch_secs: 100,
        };
        ActivationTransaction {
            schema_version: TRANSACTION_SCHEMA.into(),
            deployment: f.store.name().into(),
            activation,
            recovery: Some(recovery),
            recovery_policy: Some(policy),
            supersedes: None,
        }
    }

    #[test]
    fn rollback_reconciliation_commits_linked_records_before_the_pointer() {
        for stage in ["intent", "history", "recovery"] {
            let f = fixture();
            let lock = f.store.lock().unwrap();
            let transaction = pending_rollback(&f, &lock);
            let old_pointer = fs::read(f.store.pointer_path()).unwrap();
            retain_intent(&f, &transaction);
            if stage != "intent" {
                write_new(
                    &f.store.activation_path(3),
                    &f.authority.seal(transaction.activation.clone()).unwrap(),
                )
                .unwrap();
            }
            if stage == "recovery" {
                write_new(
                    &f.store.recovery_path(1),
                    &f.authority
                        .seal(transaction.recovery.clone().unwrap())
                        .unwrap(),
                )
                .unwrap();
            }
            assert!(f.store.active(&f.authority).is_err(), "{stage}");
            assert_eq!(fs::read(f.store.pointer_path()).unwrap(), old_pointer);
            assert_eq!(
                f.store
                    .reconcile_pending(&lock, &f.authority, 101, &|_| Ok(()))
                    .unwrap(),
                Some(transaction.activation.clone())
            );
            assert_eq!(
                f.store.recoveries(&f.authority).unwrap(),
                vec![transaction.recovery.unwrap()]
            );
            assert_eq!(
                f.store.active(&f.authority).unwrap().unwrap().release_id,
                "v1"
            );
        }
    }

    #[test]
    fn rollback_reconciliation_rechecks_policy_and_known_good_health() {
        for case in [
            "policy_changed",
            "target_crashed",
            "future_readiness",
            "target_effects_indeterminate",
            "failed_effects_indeterminate",
        ] {
            let f = fixture();
            let lock = f.store.lock().unwrap();
            let transaction = pending_rollback(&f, &lock);
            retain_intent(&f, &transaction);
            let old_pointer = fs::read(f.store.pointer_path()).unwrap();
            match case {
                "policy_changed" => {
                    let mut policy = transaction.recovery_policy.clone().unwrap();
                    policy.on_crash_loop = CrashLoopAction::Contain;
                    f.store.set_policy(&lock, &f.authority, policy).unwrap();
                }
                "target_crashed" => {
                    f.store
                        .record_health(
                            &lock,
                            &f.authority,
                            "v1",
                            HealthEvent::CrashLoop {
                                evidence: crash("later-crash"),
                            },
                        )
                        .unwrap();
                }
                "future_readiness" => {
                    f.store
                        .record_health(&lock, &f.authority, "v1", healthy("future", 102))
                        .unwrap();
                }
                "target_effects_indeterminate" | "failed_effects_indeterminate" => {
                    let release = if case == "target_effects_indeterminate" {
                        "v1"
                    } else {
                        "v2"
                    };
                    f.store
                        .record_health(
                            &lock,
                            &f.authority,
                            release,
                            native_panic(release, 9, 100, false),
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                f.store
                    .reconcile_pending(&lock, &f.authority, 101, &|_| Ok(()))
                    .is_err(),
                "{case}"
            );
            assert_eq!(fs::read(f.store.pointer_path()).unwrap(), old_pointer);
            assert!(!f.store.activation_path(3).exists());
        }
    }

    #[test]
    fn history_gaps_and_dangling_rollback_references_do_not_authorize_execution() {
        let f = fixture();
        let lock = f.store.lock().unwrap();
        let transaction = pending_rollback(&f, &lock);
        // This is the old write order's failure boundary: history and pointer
        // committed, but no recovery or authenticated transaction exists.
        let sealed = f.authority.seal(transaction.activation.clone()).unwrap();
        write_new(&f.store.activation_path(3), &sealed).unwrap();
        write_replace(&f.store.pointer_path(), &sealed).unwrap();
        assert!(f.store.active(&f.authority).is_err());
        assert!(
            f.store
                .reconcile_pending(&lock, &f.authority, 101, &|_| Ok(()))
                .is_err()
        );
        fs::rename(
            f.store.activation_path(2),
            f.store.root().join("retained-activation-2.json"),
        )
        .unwrap();
        let error = f.store.active(&f.authority).unwrap_err();
        assert!(error.to_string().contains("sequence gap"), "{error:#}");
    }

    #[test]
    fn deployment_locks_and_crash_nonces_are_bound_to_their_observations() {
        let f = fixture();
        let lock = f.store.lock().unwrap();
        let other = fixture();
        assert!(
            f.store
                .install_release(
                    &other.store.lock().unwrap(),
                    &f.authority,
                    test_release(&f.store, "v1")
                )
                .is_err()
        );
        f.store
            .install_release(&lock, &f.authority, test_release(&f.store, "v1"))
            .unwrap();
        let evidence = crash("same-session");
        for _ in 0..2 {
            f.store
                .record_health(
                    &lock,
                    &f.authority,
                    "v1",
                    HealthEvent::CrashLoop {
                        evidence: evidence.clone(),
                    },
                )
                .unwrap();
        }
        assert_eq!(f.store.health(&f.authority, "v1").unwrap().events.len(), 1);
        let mut conflicting = evidence;
        conflicting.observed_at_epoch_secs += 1;
        assert!(
            f.store
                .record_health(
                    &lock,
                    &f.authority,
                    "v1",
                    HealthEvent::CrashLoop {
                        evidence: conflicting
                    }
                )
                .is_err()
        );
        assert_eq!(f.store.health(&f.authority, "v1").unwrap().events.len(), 1);
    }

    #[test]
    fn oversized_signed_records_cannot_replace_readable_state() {
        let f = fixture();
        let path = f.store.root().join("bounded.json");
        write_new(&path, &f.authority.seal("original").unwrap()).unwrap();
        let original = fs::read(&path).unwrap();
        assert!(
            write_replace(
                &path,
                &f.authority
                    .seal("x".repeat(MAX_RECORD_BYTES as usize))
                    .unwrap()
            )
            .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), original);
    }

    #[test]
    fn pending_status_preserves_committed_history_at_every_durable_boundary() {
        for (rollback, stage) in [
            (false, "intent"),
            (false, "history"),
            (true, "intent"),
            (true, "history"),
            (true, "recovery"),
        ] {
            let f = fixture();
            let lock = f.store.lock().unwrap();
            let transaction = if rollback {
                pending_rollback(&f, &lock)
            } else {
                pending_operator(&f, &lock)
            };
            let sequence = transaction.activation.sequence;
            let previous_pointer = if rollback {
                Some(fs::read(f.store.pointer_path()).unwrap())
            } else {
                None
            };
            retain_intent(&f, &transaction);
            let intent = fs::read(f.store.transaction_path(sequence)).unwrap();
            if stage != "intent" {
                write_new(
                    &f.store.activation_path(sequence),
                    &f.authority.seal(transaction.activation.clone()).unwrap(),
                )
                .unwrap();
            }
            if stage == "recovery" {
                write_new(
                    &f.store.recovery_path(1),
                    &f.authority
                        .seal(transaction.recovery.clone().unwrap())
                        .unwrap(),
                )
                .unwrap();
            }

            let status = f.store.activation_status(&f.authority).unwrap();
            assert_eq!(status.activations.len() as u64, sequence - 1);
            assert_eq!(
                status.pending,
                Some(PendingActivation {
                    transaction_digest: record_digest(
                        &f.authority.seal(transaction.clone()).unwrap()
                    )
                    .unwrap(),
                    activation: transaction.activation.clone(),
                    planned_recovery: transaction.recovery.clone(),
                })
            );
            assert!(f.store.recoveries(&f.authority).unwrap().is_empty());
            assert!(f.store.active(&f.authority).is_err());
            match previous_pointer {
                Some(pointer) => assert_eq!(fs::read(f.store.pointer_path()).unwrap(), pointer),
                None => assert!(!f.store.pointer_path().exists()),
            }
            assert_eq!(
                fs::read(f.store.transaction_path(sequence)).unwrap(),
                intent
            );
            assert_eq!(f.store.recovery_path(1).exists(), stage == "recovery");

            f.store
                .reconcile_pending(&lock, &f.authority, 101, &|_| Ok(()))
                .unwrap();
            let committed = f.store.activation_status(&f.authority).unwrap();
            assert!(committed.pending.is_none());
            assert_eq!(committed.activations.len() as u64, sequence);
            assert_eq!(
                f.store.recoveries(&f.authority).unwrap(),
                transaction.recovery.into_iter().collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn pending_status_refuses_a_conflicting_signed_recovery_receipt() {
        let f = fixture();
        let lock = f.store.lock().unwrap();
        let transaction = pending_rollback(&f, &lock);
        retain_intent(&f, &transaction);
        let pointer = fs::read(f.store.pointer_path()).unwrap();
        let mut conflicting = transaction.recovery.unwrap();
        conflicting.crash.session_nonce = "different-crash".into();
        write_new(
            &f.store.recovery_path(1),
            &f.authority.seal(conflicting).unwrap(),
        )
        .unwrap();
        assert!(f.store.activation_status(&f.authority).is_err());
        assert!(f.store.recoveries(&f.authority).is_err());
        assert!(
            f.store
                .reconcile_pending(&lock, &f.authority, 101, &|_| Ok(()))
                .is_err()
        );
        assert_eq!(fs::read(f.store.pointer_path()).unwrap(), pointer);
        assert!(f.store.transaction_path(3).exists());
    }

    #[test]
    fn rollback_reconciliation_requires_a_previously_activated_target() {
        let f = fixture();
        let lock = f.store.lock().unwrap();
        let mut transaction = pending_rollback(&f, &lock);
        f.store
            .install_release(&lock, &f.authority, test_release(&f.store, "v3"))
            .unwrap();
        f.store
            .record_health(
                &lock,
                &f.authority,
                "v3",
                healthy("outside-deployment", 100),
            )
            .unwrap();
        transaction.activation.release_id = "v3".into();
        transaction.recovery.as_mut().unwrap().selected_release_id = Some("v3".into());
        retain_intent(&f, &transaction);
        let pointer = fs::read(f.store.pointer_path()).unwrap();
        let calls = std::cell::Cell::new(0);
        let error = f
            .store
            .reconcile_pending(&lock, &f.authority, 101, &|_| {
                calls.set(calls.get() + 1);
                Ok(())
            })
            .unwrap_err();
        assert!(
            error.to_string().contains("known-good readiness"),
            "{error:#}"
        );
        assert_eq!(calls.get(), 0);
        assert_eq!(fs::read(f.store.pointer_path()).unwrap(), pointer);
        assert!(
            f.store
                .activation_status(&f.authority)
                .unwrap()
                .pending
                .is_some()
        );
        assert!(f.store.recoveries(&f.authority).unwrap().is_empty());
    }

    fn journal_bytes(store: &DeploymentStore) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut retained = BTreeMap::new();
        for directory in ["activations", "recoveries", "transactions"] {
            let directory = store.root().join(directory);
            if directory.exists() {
                for entry in fs::read_dir(directory).unwrap() {
                    let path = entry.unwrap().path();
                    if path
                        .extension()
                        .is_some_and(|extension| extension == "json")
                    {
                        retained.insert(path.clone(), fs::read(path).unwrap());
                    }
                }
            }
        }
        retained
    }

    #[test]
    fn supersession_replaces_rejected_rollback_without_committing_its_outcome() {
        for stage in ["intent", "history", "recovery"] {
            let f = fixture();
            let lock = f.store.lock().unwrap();
            let original = pending_rollback(&f, &lock);
            retain_intent(&f, &original);
            if stage != "intent" {
                write_new(
                    &f.store.activation_path(3),
                    &f.authority.seal(original.activation.clone()).unwrap(),
                )
                .unwrap();
            }
            if stage == "recovery" {
                write_new(
                    &f.store.recovery_path(1),
                    &f.authority
                        .seal(original.recovery.clone().unwrap())
                        .unwrap(),
                )
                .unwrap();
            }
            let expected = f
                .store
                .activation_status(&f.authority)
                .unwrap()
                .pending
                .unwrap()
                .transaction_digest;
            let retained = journal_bytes(&f.store);
            // An operator withdraws the old rollback policy. Its intent must
            // remain intact, but must not permanently prevent a new release.
            let mut policy = original.recovery_policy.clone().unwrap();
            policy.on_crash_loop = CrashLoopAction::Contain;
            f.store
                .set_policy(&lock, &f.authority, policy.clone())
                .unwrap();
            assert!(
                f.store
                    .reconcile_pending(&lock, &f.authority, 101, &|_| Ok(()))
                    .is_err()
            );
            f.store
                .install_release(&lock, &f.authority, test_release(&f.store, "v3"))
                .unwrap();
            let calls = std::cell::Cell::new(0);
            let verify = |release: &ReleaseRecord| {
                assert_eq!(
                    release.release_id, "v3",
                    "the rejected rollback target must not be reauthorized"
                );
                calls.set(calls.get() + 1);
                Ok(())
            };
            let result = f
                .store
                .supersede_pending(
                    &lock,
                    &f.authority,
                    &expected,
                    "v3",
                    "replacement-operator",
                    "withdraw old recovery",
                    101,
                    &verify,
                )
                .unwrap();
            assert!(!result.already_committed);
            assert_eq!(result.activation.sequence, 4);
            assert_eq!(result.activation.reason, ActivationReason::Operator);
            assert_eq!(result.activation.recovery_sequence, None);
            assert_eq!(
                result.activation.schema_version,
                SUPERSESSION_ACTIVATION_SCHEMA
            );
            let status = f.store.activation_status(&f.authority).unwrap();
            assert!(status.pending.is_none());
            assert_eq!(
                status
                    .activations
                    .iter()
                    .map(|record| record.sequence)
                    .collect::<Vec<_>>(),
                [1, 2, 4]
            );
            assert_eq!(status.superseded.len(), 1);
            assert_eq!(status.superseded[0].activation.sequence, 3);
            assert_eq!(status.superseded[0].planned_recovery, original.recovery);
            assert_eq!(
                status.superseded[0].superseded_by_operator_id,
                "replacement-operator"
            );
            assert_eq!(status.superseded[0].reason, "withdraw old recovery");
            assert!(f.store.recoveries(&f.authority).unwrap().is_empty());
            assert_eq!(
                f.store.recovery_history(&f.authority).unwrap().len(),
                1,
                "the canceled recovery's audit slot stays reserved"
            );
            for (path, bytes) in retained {
                assert_eq!(fs::read(path).unwrap(), bytes);
            }
            let repeated = f
                .store
                .supersede_pending(
                    &lock,
                    &f.authority,
                    &expected,
                    "v3",
                    "replacement-operator",
                    "withdraw old recovery",
                    102,
                    &verify,
                )
                .unwrap();
            assert!(repeated.already_committed);
            assert_eq!(repeated.activation, result.activation);
            assert_eq!(
                calls.get(),
                2,
                "an idempotent success still rechecks current release trust"
            );

            // Later explicit operator work selects a fresh release; it cannot
            // revive crash-looped v2 or recycle the canceled recovery's nonce,
            // sequence, or be undone by a retry.
            f.store
                .install_release(&lock, &f.authority, test_release(&f.store, "v4"))
                .unwrap();
            f.store
                .activate(
                    &lock,
                    &f.authority,
                    "v4",
                    ActivationReason::Operator,
                    Some("ops"),
                    None,
                    103,
                )
                .unwrap();
            let error = f
                .store
                .recover_from_crash_loop(
                    &lock,
                    &f.authority,
                    "v4",
                    original.recovery.as_ref().unwrap().crash.clone(),
                    &policy,
                    104,
                    &|_| Ok(()),
                )
                .unwrap_err();
            assert!(
                error.to_string().contains("already has a recovery outcome"),
                "{error:#}"
            );
            let new_crash = CrashLoopEvidence {
                entrypoint: "/releases/v4/app.js".to_string(),
                safe_mode_state_path: "/releases/v4/.franken-node/safe-mode/state.json".to_string(),
                ..crash("different-session")
            };
            let new_recovery = f
                .store
                .recover_from_crash_loop(
                    &lock,
                    &f.authority,
                    "v4",
                    new_crash,
                    &policy,
                    104,
                    &|_| Ok(()),
                )
                .unwrap();
            assert_eq!(new_recovery.sequence, 2);
            assert_eq!(f.store.recoveries(&f.authority).unwrap(), [new_recovery]);
            assert!(
                f.store
                    .supersede_pending(
                        &lock,
                        &f.authority,
                        &expected,
                        "v3",
                        "replacement-operator",
                        "withdraw old recovery",
                        105,
                        &|_| panic!("stale request must be rejected first")
                    )
                    .is_err()
            );
            assert_eq!(
                f.store.active(&f.authority).unwrap().unwrap().release_id,
                "v4"
            );
        }
    }

    #[test]
    fn supersession_requires_exact_pending_identity_reason_and_current_target() {
        let f = fixture();
        let lock = f.store.lock().unwrap();
        let original = pending_operator(&f, &lock);
        retain_intent(&f, &original);
        f.store
            .install_release(&lock, &f.authority, test_release(&f.store, "v2"))
            .unwrap();
        let expected = f
            .store
            .activation_status(&f.authority)
            .unwrap()
            .pending
            .unwrap()
            .transaction_digest;
        let before = journal_bytes(&f.store);
        for (digest, reason) in [
            ("sha256:stale", "operator replacement"),
            (expected.as_str(), " "),
        ] {
            assert!(
                f.store
                    .supersede_pending(
                        &lock,
                        &f.authority,
                        digest,
                        "v2",
                        "ops",
                        reason,
                        30,
                        &|_| Ok(())
                    )
                    .is_err()
            );
        }
        assert!(
            f.store
                .supersede_pending(
                    &lock,
                    &f.authority,
                    &expected,
                    "v2",
                    "ops",
                    &"x".repeat(MAX_REASON_BYTES + 1),
                    30,
                    &|_| Ok(())
                )
                .is_err()
        );
        assert!(
            f.store
                .supersede_pending(
                    &lock,
                    &f.authority,
                    &expected,
                    "v2",
                    "ops",
                    "operator replacement",
                    30,
                    &|_| anyhow::bail!("publisher revoked")
                )
                .is_err()
        );
        assert_eq!(journal_bytes(&f.store), before);
        assert!(!f.store.pointer_path().exists());
        f.store
            .supersede_pending(
                &lock,
                &f.authority,
                &expected,
                "v2",
                "ops",
                "operator replacement",
                30,
                &|_| Ok(()),
            )
            .unwrap();
        let committed = journal_bytes(&f.store);
        assert!(
            f.store
                .supersede_pending(
                    &lock,
                    &f.authority,
                    &expected,
                    "v2",
                    "ops",
                    "changed reason",
                    31,
                    &|_| Ok(())
                )
                .is_err()
        );
        assert!(
            f.store
                .supersede_pending(
                    &lock,
                    &f.authority,
                    &expected,
                    "v2",
                    "ops",
                    "operator replacement",
                    31,
                    &|_| anyhow::bail!("replacement now revoked")
                )
                .is_err()
        );
        assert_eq!(journal_bytes(&f.store), committed);
        f.store
            .record_health(&lock, &f.authority, "v1", healthy("outside-activation", 31))
            .unwrap();
        assert!(
            f.store
                .select_known_good(&f.authority, "v2", 32, &|_| panic!(
                    "canceled attempts cannot become known-good"
                ))
                .unwrap()
                .selected
                .is_none()
        );
    }

    #[test]
    fn interrupted_supersession_can_resume_or_be_superseded_without_resurrection() {
        for replace_again in [false, true] {
            let f = fixture();
            let lock = f.store.lock().unwrap();
            let original = pending_operator(&f, &lock);
            retain_intent(&f, &original);
            for release in ["v2", "v3"] {
                f.store
                    .install_release(&lock, &f.authority, test_release(&f.store, release))
                    .unwrap();
            }
            let expected = f
                .store
                .activation_status(&f.authority)
                .unwrap()
                .pending
                .unwrap()
                .transaction_digest;
            f.store
                .supersede_pending(
                    &lock,
                    &f.authority,
                    &expected,
                    "v2",
                    "ops",
                    "first replacement",
                    30,
                    &|_| Ok(()),
                )
                .unwrap();
            let retained_intents: Vec<_> = (1..=2)
                .map(|sequence| {
                    (
                        f.store.transaction_path(sequence),
                        fs::read(f.store.transaction_path(sequence)).unwrap(),
                    )
                })
                .collect();
            // Retain the fully generated bytes outside the canonical paths to
            // reconstruct the precise durable intent-only crash boundary. The
            // CLI companion tests reach this boundary by exiting the real process.
            fs::rename(
                f.store.pointer_path(),
                f.store.root().join("retained-pointer.json"),
            )
            .unwrap();
            for sequence in 1..=2 {
                fs::rename(
                    f.store.activation_path(sequence),
                    f.store
                        .root()
                        .join(format!("retained-history-{sequence}.json")),
                )
                .unwrap();
            }
            let pending = f.store.activation_status(&f.authority).unwrap();
            assert!(pending.activations.is_empty());
            assert_eq!(pending.superseded.len(), 1);
            assert_eq!(
                pending.pending.as_ref().unwrap().activation.release_id,
                "v2"
            );
            assert!(f.store.active(&f.authority).is_err());
            let selected = if replace_again {
                let latest = pending.pending.unwrap().transaction_digest;
                f.store
                    .supersede_pending(
                        &lock,
                        &f.authority,
                        &latest,
                        "v3",
                        "another-operator",
                        "second replacement",
                        40,
                        &|release| {
                            assert_eq!(release.release_id, "v3");
                            Ok(())
                        },
                    )
                    .unwrap()
                    .activation
            } else {
                f.store
                    .supersede_pending(
                        &lock,
                        &f.authority,
                        &expected,
                        "v2",
                        "ops",
                        "first replacement",
                        40,
                        &|release| {
                            assert_eq!(release.release_id, "v2");
                            Ok(())
                        },
                    )
                    .unwrap()
                    .activation
            };
            let status = f.store.activation_status(&f.authority).unwrap();
            assert_eq!(status.activations, [selected.clone()]);
            assert_eq!(status.superseded.len(), if replace_again { 2 } else { 1 });
            assert_eq!(f.store.active(&f.authority).unwrap(), Some(selected));
            for (path, bytes) in retained_intents {
                assert_eq!(fs::read(path).unwrap(), bytes);
            }
            if replace_again {
                assert!(
                    f.store
                        .supersede_pending(
                            &lock,
                            &f.authority,
                            &expected,
                            "v2",
                            "ops",
                            "first replacement",
                            41,
                            &|_| Ok(())
                        )
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn completed_supersession_requires_its_signed_intent_forever() {
        let f = fixture();
        let lock = f.store.lock().unwrap();
        let original = pending_operator(&f, &lock);
        retain_intent(&f, &original);
        f.store
            .install_release(&lock, &f.authority, test_release(&f.store, "v2"))
            .unwrap();
        let expected = f
            .store
            .activation_status(&f.authority)
            .unwrap()
            .pending
            .unwrap()
            .transaction_digest;
        f.store
            .supersede_pending(
                &lock,
                &f.authority,
                &expected,
                "v2",
                "ops",
                "replace rejected release",
                30,
                &|_| Ok(()),
            )
            .unwrap();
        let pointer = fs::read(f.store.pointer_path()).unwrap();
        fs::rename(
            f.store.transaction_path(2),
            f.store.root().join("retained-supersession.json"),
        )
        .unwrap();
        assert!(f.store.activation_status(&f.authority).is_err());
        assert!(f.store.active(&f.authority).is_err());
        assert!(f.store.recoveries(&f.authority).is_err());
        assert!(
            f.store
                .reconcile_pending(&lock, &f.authority, 31, &|_| Ok(()))
                .is_err()
        );
        assert_eq!(fs::read(f.store.pointer_path()).unwrap(), pointer);
    }

    #[test]
    fn historical_v1_activation_preimages_and_missing_legacy_intents_stay_distinct() {
        let f = fixture();
        let lock = f.store.lock().unwrap();
        let original = pending_operator(&f, &lock);
        assert!(
            !serde_json::to_string(&original)
                .unwrap()
                .contains("supersedes")
        );
        assert!(
            !serde_json::to_string(&original.activation)
                .unwrap()
                .contains("supersedes")
        );
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
            .unwrap();
        fs::rename(
            f.store.transaction_path(1),
            f.store.root().join("retained-v1-intent.json"),
        )
        .unwrap();
        assert_eq!(
            f.store.active(&f.authority).unwrap().unwrap().release_id,
            "v1"
        );
        assert!(
            f.store
                .activation_status(&f.authority)
                .unwrap()
                .superseded
                .is_empty()
        );
    }
}
