//! Durable local observations of admitted native sessions.
//!
//! Admission is committed before the worker can start, in the existing
//! protected runtime-evidence subtree. A missing outcome remains pending after
//! restart: neither an expired deadline nor a reused/missing PID resolves it.
//! Outcomes describe what this supervisor observed, not a fleet barrier,
//! remote node attestation, rollback, or proof that external effects quiesced.
//! Before updating the inventory, a supervisor durably retains its signed
//! outcome. Fleet reconciliation may recover that exact observation after a
//! crash or failed database write; ordinary inventory inspection stays read-only.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use fsqlite::compat::{Transaction, TransactionExt};
use fsqlite::{Connection, SqliteValue};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::control_plane::fleet_transport::{
    FleetActionRecord, FleetApplicationCheckpoint, MAX_NATIVE_SESSION_MAINTENANCE_HOLDS,
    NATIVE_SESSION_DRAIN_ATTESTATION_SCHEMA, NativeSessionDrainAttestation,
    NativeSessionDrainCheckpoint, fleet_action_snapshot_prefix, fleet_application_checkpoint,
    fleet_native_session_holds, validate_action_id, validate_node_id, validate_zone_id,
};

use super::engine_dispatcher::{
    HostEffectLedger, NATIVE_EFFECT_INTERRUPTION_EVIDENCE_SCHEMA,
    NATIVE_SESSION_MAX_DIAGNOSTIC_BYTES, NATIVE_SESSION_MAX_EFFECT_WAL_EVENTS,
    NATIVE_SESSION_MAX_EFFECT_WAL_STREAM_BYTES, NATIVE_SESSION_MAX_REQUEST_BYTES,
    NativeEffectInterruptionEvidence, NativeEffectWalState,
    RUNTIME_EVIDENCE_CAPTURE_DIR_RELATIVE_PATH, RUNTIME_EVIDENCE_PRODUCT_STATE_DIRECTORY,
    RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH, RUNTIME_EVIDENCE_STATE_DIRECTORY,
    RuntimeEvidenceIdentityCapture, create_new_runtime_evidence_private_file,
    ensure_runtime_evidence_directory, load_or_create_runtime_evidence_product_root,
    load_runtime_evidence_product_root, prepare_runtime_evidence_directories,
    read_runtime_evidence_private_file, runtime_evidence_user_state_home,
    validate_runtime_evidence_private_file_metadata,
};

const INVENTORY_SCHEMA: &str = "franken-node/native-session-inventory/v1";
const INVENTORY_FILE: &str = "native-sessions.db";
const MAX_STORED_SESSIONS: usize = crate::capacity_defaults::base::STANDARD;
const MAX_IDENTITY_CAPTURES: usize = crate::capacity_defaults::base::LARGE;
// Do not introduce an accounting ceiling below the existing admitted request:
// identity strings can expand in JSON even within their raw 2MiB trust bound.
const MAX_ADMISSION_BYTES: usize = NATIVE_SESSION_MAX_REQUEST_BYTES;
const ADMISSION_RECEIPT_SCHEMA: &str = "franken-node/native-session-admission-receipt/v1";
const ADMISSION_RECEIPT_DIRECTORY: &str = "session-admissions";
const MAX_ADMISSION_RECEIPT_BYTES: usize = 4 * 1024;
const MAX_OUTCOME_BYTES: usize =
    NATIVE_SESSION_MAX_EFFECT_WAL_STREAM_BYTES + NATIVE_SESSION_MAX_DIAGNOSTIC_BYTES;
const OUTCOME_RECEIPT_SCHEMA: &str = "franken-node/native-session-outcome-receipt/v1";
const OUTCOME_RECEIPT_DIRECTORY: &str = "session-outcomes";
const MAX_OUTCOME_RECEIPT_BYTES: usize = MAX_OUTCOME_BYTES + 1024;
// Reserve the maximum outcome for every pending admission. Recording a
// terminal/unknown outcome therefore remains possible at admission capacity.
const MAX_RESERVED_BYTES: usize = crate::capacity_defaults::base::SMALL * 1024 * 1024;
// Preserve the existing inventory population bound, including historical
// captures whose project is unknown. UUID spelling is bounded below; allow
// JSON punctuation and fixed identity/checkpoint metadata without truncation.
const MAX_DRAIN_BYTES: usize = (MAX_STORED_SESSIONS + MAX_IDENTITY_CAPTURES) * 68
    + MAX_NATIVE_SESSION_MAINTENANCE_HOLDS * 132
    + 64 * 1024;
const MAX_RETAINED_DRAINS: usize = crate::capacity_defaults::base::STANDARD;
// A supervised deployment adds its operator project to the release's own
// authority. More aliases require an explicit bounded ownership protocol.
const MAX_ADDITIONAL_CONTROL_SCOPES: usize = 1;

pub(crate) fn fleet_policy_observation_digest(
    policy: &crate::control_plane::fleet_transport::ActiveFleetPolicy,
) -> Result<String> {
    let bytes = serde_json::to_vec(policy).context("serialize admitted fleet policy")?;
    let mut digest = Sha256::new();
    digest.update(b"franken-node/native-session-fleet-policy-observation/v1\0");
    digest.update(u64::try_from(bytes.len())?.to_be_bytes());
    digest.update(bytes);
    Ok(hex::encode(digest.finalize()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSessionControlScope {
    /// A retained canonical operator project, not a guest filesystem grant.
    pub project_root: PathBuf,
    /// Fence generation captured before the final live authority recheck.
    pub admission_generation: u64,
    /// Exact additional owner's admitted policy, when one was present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fleet_policy_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSessionAdmission {
    pub session_nonce: String,
    pub product_root_key_id: String,
    pub identity_capture_path: PathBuf,
    /// Engine evidence activation epoch; this is not a fleet control epoch.
    pub security_epoch: u64,
    pub admitted_at: DateTime<Utc>,
    pub project_root: PathBuf,
    pub entrypoint: PathBuf,
    pub dependency_ids: Vec<String>,
    pub configured_node_id: Option<String>,
    pub fleet_zone_id: Option<String>,
    /// Digest of the exact admitted ActiveFleetPolicy, if one was present.
    /// It is an observation binding, not an action application acknowledgement.
    pub fleet_policy_sha256: Option<String>,
    /// Parent-authenticated process admission, never inferred from a profile.
    /// Historical records omit this and cannot establish descendant cleanup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_spawn_authority_granted: Option<bool>,
    /// Additional authenticated control owners, normally the deployment's
    /// operator project. `Some([])` explicitly means no additional owner.
    /// Historical absence is unknown and must not hide a retained obligation
    /// from any project's drain. Omission preserves old receipt preimages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_scopes: Option<Vec<NativeSessionControlScope>>,
}

impl NativeSessionAdmission {
    fn belongs_to_control_scope(&self, project_root: &Path) -> bool {
        self.project_root == project_root
            || self.control_scopes.as_ref().is_none_or(|scopes| {
                scopes
                    .iter()
                    .any(|scope| scope.project_root == project_root)
            })
    }
}

/// A retained local drain over one exact admitted population. The action
/// checkpoint binds the validated ordered history; only the fleet agent's separate
/// application checkpoint establishes that it applied those actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSessionDrainReport {
    pub drain_id: String,
    pub generation: u64,
    pub project_root: PathBuf,
    pub node_id: String,
    pub zone_id: String,
    pub session_nonces: Vec<String>,
    pub checkpoint: NativeSessionDrainCheckpoint,
    /// Immutable action IDs that independently keep this project's admission
    /// fenced. Clearing one owner cannot release any other owner's hold.
    #[serde(default)]
    pub maintenance_hold_ids: Vec<String>,
    /// Local terminal accounting is not a distributed epoch/barrier proof.
    pub fleet_quiescence_certified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredNativeSessionDrain {
    drain_id: String,
    generation: u64,
    project_root: PathBuf,
    node_id: String,
    zone_id: String,
    session_nonces: Vec<String>,
    actions: FleetApplicationCheckpoint,
    fence_held: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    maintenance_hold_ids: Vec<String>,
    /// Set only by finish after the caller successfully applied this exact
    /// snapshot. A terminal population alone cannot skip an unapplied hold.
    #[serde(default)]
    actions_applied: bool,
    /// Signed once when the initial cohort is sealed. Historical unsealed
    /// drains remain inspectable but cannot become authenticated observations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    census_signature_hex: Option<String>,
}

impl StoredNativeSessionDrain {
    fn census_preimage(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct Census<'a> {
            drain_id: &'a str,
            generation: u64,
            project_root: &'a str,
            node_id: &'a str,
            zone_id: &'a str,
            session_nonces: &'a [String],
            actions: &'a FleetApplicationCheckpoint,
            maintenance_hold_ids: &'a [String],
        }
        let bytes = bounded_json(
            &Census {
                drain_id: &self.drain_id,
                generation: self.generation,
                project_root: project_key(&self.project_root)?,
                node_id: &self.node_id,
                zone_id: &self.zone_id,
                session_nonces: &self.session_nonces,
                actions: &self.actions,
                maintenance_hold_ids: &self.maintenance_hold_ids,
            },
            MAX_DRAIN_BYTES,
        )?;
        let mut payload = b"franken-node/native-session-drain-census/v1\0".to_vec();
        payload.extend_from_slice(&u64::try_from(bytes.len())?.to_be_bytes());
        payload.extend_from_slice(bytes.as_bytes());
        Ok(payload)
    }

    fn seal_census(&mut self, root: &ed25519_dalek::SigningKey) -> Result<()> {
        use ed25519_dalek::Signer as _;
        if self.census_signature_hex.is_some() {
            bail!("native-session drain census is already sealed");
        }
        self.census_signature_hex =
            Some(hex::encode(root.sign(&self.census_preimage()?).to_bytes()));
        Ok(())
    }

    fn verify_census(&self, root: &ed25519_dalek::VerifyingKey) -> Result<()> {
        let signature_hex = self
            .census_signature_hex
            .as_deref()
            .context("native-session drain has no authenticated initial census; a new action snapshot is required")?;
        if signature_hex.len() != 128 {
            bail!("native-session drain census signature has invalid length");
        }
        let bytes = hex::decode(signature_hex)
            .context("native-session drain census signature is not hexadecimal")?;
        let signature = ed25519_dalek::Signature::from_slice(&bytes)
            .context("native-session drain census signature has invalid length")?;
        root.verify_strict(&self.census_preimage()?, &signature)
            .context("native-session drain retained census was altered")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSessionProcessObservation {
    NotSpawned,
    WorkerReaped,
    Unproven,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSessionOutcomeKind {
    Completed,
    ExecutionFailed,
    /// Live control stopped the attempt, and its reaped worker supplied a
    /// validated final ledger. This is not a containment or fleet certificate.
    ControlStopped,
    Interrupted,
    TelemetryFailed,
    Panicked,
    SupervisionIncomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeSessionEffectObservation {
    NotStarted,
    /// The parent validated this final ledger before recording its summary.
    /// The digest is not a substitute for exporting the signed ledger itself.
    FinalLedgerObserved {
        effect_count: usize,
        allowed_count: usize,
        denied_count: usize,
        failed_count: usize,
        chain_head_hash: String,
        ledger_sha256: String,
    },
    /// Preserve the complete bounded parent-observed WAL evidence. Provider
    /// returns remain distinct from canonical committed/denied effect receipts.
    Interrupted {
        evidence: Box<NativeEffectInterruptionEvidence>,
    },
    Unknown,
}

impl NativeSessionEffectObservation {
    pub(crate) fn from_verified_ledger(ledger: Option<&HostEffectLedger>) -> Self {
        let Some(ledger) = ledger else {
            return Self::Unknown;
        };
        match serde_json::to_vec(ledger) {
            Ok(bytes) => Self::FinalLedgerObserved {
                effect_count: ledger.effect_count,
                allowed_count: ledger.allowed_count,
                denied_count: ledger.denied_count,
                failed_count: ledger.failed_count,
                chain_head_hash: ledger.chain_head_hash.clone(),
                ledger_sha256: hex::encode(Sha256::digest(bytes)),
            },
            Err(_) => Self::Unknown,
        }
    }

    fn unknown(&self) -> bool {
        match self {
            // A signed failure is terminal local accounting, not evidence
            // that an admitted operation made no external change. In
            // particular, cancellation can follow a request reaching its peer.
            Self::FinalLedgerObserved { failed_count, .. } => *failed_count > 0,
            Self::Interrupted { .. } | Self::Unknown => true,
            Self::NotStarted => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSessionOutcome {
    pub observed_at: DateTime<Utc>,
    pub kind: NativeSessionOutcomeKind,
    pub process: NativeSessionProcessObservation,
    /// Only the existing pinned Bubblewrap containment-empty observation sets
    /// this true. Reaping a process-group worker does not establish it.
    pub containment_empty_observed: bool,
    pub effects: NativeSessionEffectObservation,
}

/// A product supervisor's observation, authenticated independently of the
/// database it can repair. It never converts unknown effects or an unreaped
/// worker into a terminal observation. The admission commitment binds the
/// project, entrypoint, authority, captured identity and exact launch nonce.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeSessionOutcomeReceipt {
    schema_version: String,
    session_nonce: String,
    product_root_key_id: String,
    admission_sha256: String,
    outcome: NativeSessionOutcome,
    signature_hex: String,
}

/// Immutable authentication of the complete admission, including its project
/// attribution. The runtime identity capture binds only nonce/root/epoch; a
/// pending database row cannot supply its own authoritative project identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeSessionAdmissionReceipt {
    schema_version: String,
    session_nonce: String,
    product_root_key_id: String,
    admission_sha256: String,
    signature_hex: String,
}

fn admission_digest(admission: &NativeSessionAdmission) -> Result<String> {
    let bytes = bounded_json(admission, MAX_ADMISSION_BYTES)?;
    let mut digest = Sha256::new();
    digest.update(b"franken-node/native-session-admission/v1\0");
    digest.update(u64::try_from(bytes.len())?.to_be_bytes());
    digest.update(bytes.as_bytes());
    Ok(hex::encode(digest.finalize()))
}

impl NativeSessionAdmissionReceipt {
    fn preimage(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct Payload<'a> {
            schema_version: &'a str,
            session_nonce: &'a str,
            product_root_key_id: &'a str,
            admission_sha256: &'a str,
        }
        let bytes = bounded_json(
            &Payload {
                schema_version: &self.schema_version,
                session_nonce: &self.session_nonce,
                product_root_key_id: &self.product_root_key_id,
                admission_sha256: &self.admission_sha256,
            },
            MAX_ADMISSION_RECEIPT_BYTES,
        )?;
        let mut preimage = b"franken-node/native-session-admission-signature/v1\0".to_vec();
        preimage.extend_from_slice(&u64::try_from(bytes.len())?.to_be_bytes());
        preimage.extend_from_slice(bytes.as_bytes());
        Ok(preimage)
    }

    fn issue(admission: &NativeSessionAdmission, root: &ed25519_dalek::SigningKey) -> Result<Self> {
        use ed25519_dalek::Signer as _;
        validate_admission(admission)?;
        let mut receipt = Self {
            schema_version: ADMISSION_RECEIPT_SCHEMA.to_owned(),
            session_nonce: admission.session_nonce.clone(),
            product_root_key_id: admission.product_root_key_id.clone(),
            admission_sha256: admission_digest(admission)?,
            signature_hex: String::new(),
        };
        receipt.signature_hex = hex::encode(root.sign(&receipt.preimage()?).to_bytes());
        receipt.verify(admission, &root.verifying_key())?;
        Ok(receipt)
    }

    fn verify(
        &self,
        admission: &NativeSessionAdmission,
        trusted_root: &ed25519_dalek::VerifyingKey,
    ) -> Result<()> {
        validate_admission(admission)?;
        if self.schema_version != ADMISSION_RECEIPT_SCHEMA
            || self.session_nonce != admission.session_nonce
            || self.product_root_key_id != admission.product_root_key_id
            || self.product_root_key_id
                != format!("ed25519:{}", hex::encode(trusted_root.as_bytes()))
            || self.admission_sha256 != admission_digest(admission)?
            || self.signature_hex.len() != 128
        {
            bail!(
                "native-session admission receipt is not bound to this admission and trusted root"
            );
        }
        let bytes = hex::decode(&self.signature_hex)
            .context("native-session admission receipt signature is not hexadecimal")?;
        let signature = ed25519_dalek::Signature::from_slice(&bytes)
            .context("native-session admission receipt signature has invalid length")?;
        trusted_root
            .verify_strict(&self.preimage()?, &signature)
            .context("native-session admission receipt signature verification failed")
    }
}

impl NativeSessionOutcomeReceipt {
    fn preimage(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct Payload<'a> {
            schema_version: &'a str,
            session_nonce: &'a str,
            product_root_key_id: &'a str,
            admission_sha256: &'a str,
            outcome: &'a NativeSessionOutcome,
        }

        let payload = bounded_json(
            &Payload {
                schema_version: &self.schema_version,
                session_nonce: &self.session_nonce,
                product_root_key_id: &self.product_root_key_id,
                admission_sha256: &self.admission_sha256,
                outcome: &self.outcome,
            },
            MAX_OUTCOME_RECEIPT_BYTES,
        )?;
        let mut preimage = b"franken-node/native-session-outcome-signature/v1\0".to_vec();
        preimage.extend_from_slice(&u64::try_from(payload.len())?.to_be_bytes());
        preimage.extend_from_slice(payload.as_bytes());
        Ok(preimage)
    }

    fn issue(
        admission: &NativeSessionAdmission,
        outcome: &NativeSessionOutcome,
        root: &ed25519_dalek::SigningKey,
    ) -> Result<Self> {
        use ed25519_dalek::Signer as _;

        validate_admission(admission)?;
        validate_outcome(admission, outcome)?;
        let mut receipt = Self {
            schema_version: OUTCOME_RECEIPT_SCHEMA.to_owned(),
            session_nonce: admission.session_nonce.clone(),
            product_root_key_id: admission.product_root_key_id.clone(),
            admission_sha256: admission_digest(admission)?,
            outcome: outcome.clone(),
            signature_hex: String::new(),
        };
        receipt.signature_hex = hex::encode(root.sign(&receipt.preimage()?).to_bytes());
        receipt.verify(admission, &root.verifying_key())?;
        Ok(receipt)
    }

    fn verify(
        &self,
        admission: &NativeSessionAdmission,
        trusted_root: &ed25519_dalek::VerifyingKey,
    ) -> Result<()> {
        if self.schema_version != OUTCOME_RECEIPT_SCHEMA
            || self.session_nonce != admission.session_nonce
            || self.product_root_key_id != admission.product_root_key_id
            || self.product_root_key_id
                != format!("ed25519:{}", hex::encode(trusted_root.as_bytes()))
            || self.admission_sha256 != admission_digest(admission)?
            || self.signature_hex.len() != 128
        {
            bail!("native-session outcome receipt is not bound to this admission and trusted root");
        }
        let bytes = hex::decode(&self.signature_hex)
            .context("native-session outcome receipt signature is not hexadecimal")?;
        let signature = ed25519_dalek::Signature::from_slice(&bytes)
            .context("native-session outcome receipt signature has invalid length")?;
        trusted_root
            .verify_strict(&self.preimage()?, &signature)
            .context("native-session outcome receipt signature verification failed")?;
        validate_outcome(admission, &self.outcome)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSessionInventoryRecord {
    pub admission: NativeSessionAdmission,
    pub outcome: Option<NativeSessionOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UntrackedNativeIdentityCapture {
    pub session_nonce: String,
    pub product_root_key_id: String,
    pub identity_capture_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSessionInventoryReport {
    pub schema_version: String,
    pub scope: String,
    pub coverage: String,
    pub quiescence_certified: bool,
    pub database_path: PathBuf,
    pub store_present: bool,
    pub project_root: Option<PathBuf>,
    pub total_stored_sessions: usize,
    pub pending_sessions: usize,
    /// Parent-observed worker reap, not remote effect or fleet quiescence.
    pub terminal_sessions: usize,
    pub unproven_process_sessions: usize,
    /// Includes signed final ledgers with failed admitted attempts: knowing
    /// that a provider returned does not resolve their possible external effects.
    pub unknown_effect_sessions: usize,
    pub records: Vec<NativeSessionInventoryRecord>,
    /// Older captures and captures provisioned before admission failed have no
    /// lifecycle evidence. Their project is unknown, so filtering never hides
    /// them. A capture alone never proves a worker was actually spawned.
    pub untracked_identity_captures: Vec<UntrackedNativeIdentityCapture>,
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_admission(admission: &NativeSessionAdmission) -> Result<()> {
    uuid::Uuid::parse_str(&admission.session_nonce).context("invalid inventory session nonce")?;
    if !admission.project_root.is_absolute()
        || !admission.entrypoint.starts_with(&admission.project_root)
        || !admission.identity_capture_path.is_absolute()
    {
        bail!("native-session admission paths are not bound to an absolute project root");
    }
    if let Some(scopes) = &admission.control_scopes {
        if scopes.len() > MAX_ADDITIONAL_CONTROL_SCOPES {
            bail!("native-session admission exceeds its additional control-scope bound");
        }
        for scope in scopes {
            let key = project_key(&scope.project_root)?;
            if scope.project_root == admission.project_root
                || key.len() > 4096
                || key.as_bytes().contains(&0)
                || scope.project_root.components().count() > 128
                || scope
                    .fleet_policy_sha256
                    .as_deref()
                    .is_some_and(|value| !valid_digest(value))
            {
                bail!(
                    "native-session additional control scope is duplicate, unbounded or has an invalid policy digest"
                );
            }
        }
    }
    if admission.fleet_zone_id.is_some() != admission.fleet_policy_sha256.is_some() {
        bail!("native-session fleet observation is incomplete");
    }
    if !admission
        .product_root_key_id
        .strip_prefix("ed25519:")
        .is_some_and(valid_digest)
        || admission
            .fleet_policy_sha256
            .as_deref()
            .is_some_and(|value| !valid_digest(value))
    {
        bail!("native-session admission contains an invalid identity or digest");
    }
    Ok(())
}

fn validate_outcome(
    admission: &NativeSessionAdmission,
    outcome: &NativeSessionOutcome,
) -> Result<()> {
    use NativeSessionEffectObservation as Effects;
    use NativeSessionOutcomeKind as Kind;
    use NativeSessionProcessObservation as Process;

    if outcome.process == Process::NotSpawned {
        if outcome.kind != Kind::SupervisionIncomplete
            || outcome.effects != Effects::NotStarted
            || outcome.containment_empty_observed
        {
            bail!("unspawned native session has impossible outcome observations");
        }
    } else if outcome.effects == Effects::NotStarted {
        bail!("spawned native session cannot assert no effects were started");
    }
    if matches!(
        outcome.kind,
        Kind::Completed
            | Kind::ExecutionFailed
            | Kind::ControlStopped
            | Kind::TelemetryFailed
            | Kind::Panicked
    ) && outcome.process != Process::WorkerReaped
    {
        bail!("native-session final response lacks a parent-observed worker reap");
    }
    if outcome.kind == Kind::ControlStopped
        && !matches!(outcome.effects, Effects::FinalLedgerObserved { .. })
    {
        bail!("cooperatively stopped native session lacks a validated final ledger");
    }
    match &outcome.effects {
        Effects::FinalLedgerObserved {
            effect_count,
            allowed_count,
            denied_count,
            failed_count,
            chain_head_hash,
            ledger_sha256,
        } => {
            if !matches!(
                outcome.kind,
                Kind::Completed | Kind::ExecutionFailed | Kind::ControlStopped
            ) || allowed_count
                .checked_add(*denied_count)
                .and_then(|value| value.checked_add(*failed_count))
                != Some(*effect_count)
                || !chain_head_hash
                    .strip_prefix("sha256:")
                    .is_some_and(valid_digest)
                || !valid_digest(ledger_sha256)
            {
                bail!("native-session final ledger summary is inconsistent");
            }
        }
        Effects::Interrupted { evidence } => {
            let completed = evidence
                .entries
                .iter()
                .filter(|entry| entry.state == NativeEffectWalState::ProviderReturned)
                .count();
            let interrupted = evidence.entries.len().saturating_sub(completed);
            if outcome.kind != Kind::Interrupted
                || evidence.schema_version != NATIVE_EFFECT_INTERRUPTION_EVIDENCE_SCHEMA
                || evidence.session_nonce != admission.session_nonce
                || evidence.replay_certified
                || evidence.journal_event_cap != NATIVE_SESSION_MAX_EFFECT_WAL_EVENTS
                || evidence.entries.len() > evidence.journal_event_cap
                || evidence.completed_effect_count != completed
                || evidence.interrupted_effect_count != interrupted
                || interrupted > 1
                || completed
                    .checked_mul(2)
                    .and_then(|events| events.checked_add(interrupted))
                    .is_none_or(|events| events > evidence.journal_event_cap)
                || evidence.journal_complete != evidence.protocol_error.is_none()
                || !matches!(
                    evidence.terminal_state.as_str(),
                    "timeout_indeterminate"
                        | "control_indeterminate"
                        | "timeout_cleanup_unproven"
                        | "control_cleanup_unproven"
                )
                || evidence.control_trigger.is_some()
                    != evidence.terminal_state.starts_with("control_")
            {
                bail!("native-session interruption evidence is inconsistent");
            }
            for (sequence, entry) in evidence.entries.iter().enumerate() {
                if entry.sequence != u64::try_from(sequence)?
                    || entry.effect_kind.trim().is_empty()
                    || (entry.state == NativeEffectWalState::InterruptedIndeterminate
                        && sequence + 1 != evidence.entries.len())
                    || !entry
                        .request_hash
                        .strip_prefix("sha256:")
                        .is_some_and(valid_digest)
                {
                    bail!("native-session interruption entry is inconsistent");
                }
            }
        }
        Effects::NotStarted | Effects::Unknown => {
            if outcome.kind == Kind::Interrupted {
                bail!("native-session interruption is missing its observed effect evidence");
            }
        }
    }
    Ok(())
}

fn verify_admission_capture(
    protected_root: &Path,
    admission: &NativeSessionAdmission,
) -> Result<()> {
    let capture_directory = protected_root.join(RUNTIME_EVIDENCE_CAPTURE_DIR_RELATIVE_PATH);
    if admission.identity_capture_path.parent() != Some(capture_directory.as_path()) {
        bail!("native-session capture is outside its protected capture directory");
    }
    ensure_runtime_evidence_directory(&capture_directory, true)?;
    ensure_runtime_evidence_directory(&protected_root.join("keys"), true)?;
    let bytes = read_runtime_evidence_private_file(&admission.identity_capture_path, 64 * 1024)?;
    let capture: RuntimeEvidenceIdentityCapture = serde_json::from_slice(&bytes)?;
    let product_root = load_runtime_evidence_product_root(
        &protected_root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH),
    )?;
    capture.verify_with_product_root(&product_root.verifying_key())?;
    if capture.session_nonce != admission.session_nonce
        || capture.product_root_key_id != admission.product_root_key_id
        || capture
            .evidence_verification_identity
            .key_provenance
            .activation_epoch
            .as_u64()
            != admission.security_epoch
    {
        bail!("native-session admission does not match its product-signed capture");
    }
    Ok(())
}

fn bounded_json<T: Serialize>(value: &T, maximum: usize) -> Result<String> {
    let json = serde_json::to_string(value).context("serialize native-session inventory")?;
    if json.len() > maximum {
        bail!("native-session inventory record exceeds its {maximum}-byte bound");
    }
    Ok(json)
}

fn parse_json<T: serde::de::DeserializeOwned>(value: &SqliteValue, maximum: usize) -> Result<T> {
    let SqliteValue::Text(raw) = value else {
        bail!("native-session inventory contains a non-text JSON column");
    };
    if raw.len() > maximum {
        bail!("stored native-session inventory record exceeds its {maximum}-byte bound");
    }
    serde_json::from_str(raw).context("decode native-session inventory record")
}

fn check_bounds(tx: &Transaction<'_>) -> Result<()> {
    check_bounds_with_limits(tx, MAX_STORED_SESSIONS, MAX_RESERVED_BYTES)
}

fn check_bounds_with_limits(
    tx: &Transaction<'_>,
    max_records: usize,
    max_bytes: usize,
) -> Result<()> {
    let rows = tx.query(&format!(
        "SELECT COUNT(*), COALESCE(SUM(LENGTH(CAST(admission_json AS BLOB)) + CASE
         WHEN outcome_json IS NULL THEN {MAX_OUTCOME_BYTES}
         ELSE LENGTH(CAST(outcome_json AS BLOB)) END), 0) FROM native_sessions;"
    ))?;
    let [row] = rows.as_slice() else {
        bail!("native-session inventory count query was invalid");
    };
    let [SqliteValue::Integer(count), SqliteValue::Integer(bytes)] = row.values() else {
        bail!("native-session inventory size query was invalid");
    };
    let count = usize::try_from(*count)?;
    let bytes = usize::try_from(*bytes)?;
    if count > max_records || bytes > max_bytes {
        bail!(
            "native-session inventory capacity exceeded: {count}/{max_records} retained sessions, \
             {bytes}/{max_bytes} reserved bytes; refusing to discard retained sessions"
        );
    }
    Ok(())
}

fn validate_private_path_if_present(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                bail!(
                    "native-session inventory path {} is a symlink",
                    path.display()
                );
            }
            validate_runtime_evidence_private_file_metadata(path, &metadata)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt as _;
                if metadata.nlink() != 1 || metadata.uid() != rustix::process::geteuid().as_raw() {
                    bail!("native-session inventory file must be owned and have a single link");
                }
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

// fsqlite's Unix VFS uses default OpenOptions modes for new WAL/SHM files.
// Their parent is already owner-only and masked from the worker. Restrict
// those files through a no-follow descriptor after checking owner, identity,
// and link count, never chmod a pathname that may have changed underneath us.
fn protect_sidecar_if_present(path: &Path) -> Result<()> {
    let observed = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("inspect native-session inventory sidecar"),
    };
    if observed.file_type().is_symlink() || !observed.is_file() {
        bail!("native-session inventory sidecar is not a regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, open};
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let file = std::fs::File::from(open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let opened = file.metadata()?;
        if observed.dev() != opened.dev()
            || observed.ino() != opened.ino()
            || opened.uid() != rustix::process::geteuid().as_raw()
            || opened.nlink() != 1
            || !opened.is_file()
        {
            bail!("native-session inventory sidecar identity or owner is invalid");
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        validate_runtime_evidence_private_file_metadata(path, &file.metadata()?)?;
    }
    #[cfg(not(unix))]
    validate_runtime_evidence_private_file_metadata(path, &observed)?;
    Ok(())
}

fn protect_sidecars(protected_root: &Path) -> Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        protect_sidecar_if_present(&protected_root.join(format!("{INVENTORY_FILE}{suffix}")))?;
    }
    Ok(())
}

fn open_inventory(protected_root: &Path, create: bool) -> Result<Option<Connection>> {
    let database_path = protected_root.join(INVENTORY_FILE);
    let database_name = database_path
        .to_str()
        .context("native-session inventory path must be UTF-8; refusing a lossy path alias")?;
    if !validate_private_path_if_present(&database_path)? {
        if !create {
            return Ok(None);
        }
        create_new_runtime_evidence_private_file(&database_path, &[])?;
        validate_private_path_if_present(&database_path)?;
    }
    protect_sidecars(protected_root)?;
    let connection =
        Connection::open(database_name).context("open protected native-session inventory")?;
    for pragma in [
        "PRAGMA journal_mode=WAL;",
        "PRAGMA synchronous=FULL;",
        "PRAGMA busy_timeout=1000;",
    ] {
        connection
            .query(pragma)
            .context("configure native-session inventory durability")?;
    }
    if create {
        let mut tx = connection.transaction()?;
        tx.execute(
            "CREATE TABLE IF NOT EXISTS native_sessions (
                session_nonce TEXT PRIMARY KEY NOT NULL,
                admission_json TEXT NOT NULL,
                outcome_json TEXT
            );",
        )?;
        tx.execute(
            "CREATE TABLE IF NOT EXISTS native_session_drains (
                drain_id TEXT PRIMARY KEY NOT NULL,
                project_root TEXT NOT NULL,
                generation INTEGER NOT NULL,
                state_json TEXT NOT NULL,
                UNIQUE(project_root, generation)
            );",
        )?;
        tx.execute(
            "CREATE TABLE IF NOT EXISTS native_session_admission_serialization (
                project_root TEXT PRIMARY KEY NOT NULL,
                transaction_nonce TEXT NOT NULL
            );",
        )?;
        tx.commit()?;
    }
    protect_sidecars(protected_root)?;
    Ok(Some(connection))
}

fn retry_snapshot_conflict<T>(mut operation: impl FnMut() -> Result<T>) -> Result<T> {
    for attempt in 0..6_u32 {
        match operation() {
            Err(error) if attempt < 5 => {
                let message = format!("{error:#}").to_ascii_lowercase();
                if !message.contains("snapshot conflict")
                    && !message.contains("database is busy")
                    && !message.contains("database is locked")
                {
                    return Err(error);
                }
                std::thread::sleep(std::time::Duration::from_millis(20 << attempt));
            }
            result => return result,
        }
    }
    unreachable!("bounded retry loop always returns on its final attempt")
}

fn outcome_receipt_path(protected_root: &Path, nonce: &str) -> PathBuf {
    // Hash the exact spelling so accepted UUID spellings cannot alias another
    // admission's retained file or introduce path components.
    protected_root.join(OUTCOME_RECEIPT_DIRECTORY).join(format!(
        "{}.json",
        hex::encode(Sha256::digest(nonce.as_bytes()))
    ))
}

fn admission_receipt_path(protected_root: &Path, nonce: &str) -> PathBuf {
    protected_root
        .join(ADMISSION_RECEIPT_DIRECTORY)
        .join(format!(
            "{}.json",
            hex::encode(Sha256::digest(nonce.as_bytes()))
        ))
}

fn read_admission_receipt(
    protected_root: &Path,
    admission: &NativeSessionAdmission,
    trusted_root: &ed25519_dalek::VerifyingKey,
) -> Result<Option<NativeSessionAdmissionReceipt>> {
    let path = admission_receipt_path(protected_root, &admission.session_nonce);
    if !validate_private_path_if_present(&path)? {
        return Ok(None);
    }
    let bytes = read_runtime_evidence_private_file(&path, MAX_ADMISSION_RECEIPT_BYTES)?;
    let receipt: NativeSessionAdmissionReceipt = serde_json::from_slice(&bytes)
        .context("decode retained native-session admission receipt")?;
    receipt.verify(admission, trusted_root)?;
    Ok(Some(receipt))
}

fn retain_admission_receipt(
    protected_root: &Path,
    admission: &NativeSessionAdmission,
) -> Result<()> {
    use std::io::Write as _;
    verify_admission_capture(protected_root, admission)?;
    let root = load_runtime_evidence_product_root(
        &protected_root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH),
    )?;
    let receipt = NativeSessionAdmissionReceipt::issue(admission, &root)?;
    let bytes = bounded_json(&receipt, MAX_ADMISSION_RECEIPT_BYTES)?;
    let directory = protected_root.join(ADMISSION_RECEIPT_DIRECTORY);
    ensure_runtime_evidence_directory(&directory, true)?;
    let path = admission_receipt_path(protected_root, &admission.session_nonce);
    let mut staged = tempfile::NamedTempFile::new_in(&directory)
        .context("stage private native-session admission receipt")?;
    staged.write_all(bytes.as_bytes())?;
    staged.as_file().sync_all()?;
    match staged.persist_noclobber(&path) {
        Ok(_) => {}
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            read_admission_receipt(protected_root, admission, &root.verifying_key())?
                .context("retained native-session admission disappeared during publication")?;
        }
        Err(error) => return Err(error.error).context("publish native-session admission receipt"),
    }
    // A receipt with no committed inventory row never certifies that the
    // worker ran or stopped; its identity capture stays untracked/indeterminate.
    #[cfg(unix)]
    {
        std::fs::File::open(&directory)?.sync_all()?;
        std::fs::File::open(protected_root)?.sync_all()?;
    }
    Ok(())
}

fn read_outcome_receipt(
    protected_root: &Path,
    admission: &NativeSessionAdmission,
    trusted_root: &ed25519_dalek::VerifyingKey,
) -> Result<Option<NativeSessionOutcomeReceipt>> {
    let path = outcome_receipt_path(protected_root, &admission.session_nonce);
    if !validate_private_path_if_present(&path)? {
        return Ok(None);
    }
    let bytes = read_runtime_evidence_private_file(&path, MAX_OUTCOME_RECEIPT_BYTES)?;
    let receipt: NativeSessionOutcomeReceipt =
        serde_json::from_slice(&bytes).context("decode retained native-session outcome receipt")?;
    receipt.verify(admission, trusted_root)?;
    Ok(Some(receipt))
}

#[derive(Default)]
struct NativeSessionRecordAuthority {
    /// These records cannot supply trusted project attribution. Preserve them
    /// in every project census until independent signed evidence resolves them.
    unproven_admissions: BTreeSet<String>,
    /// An unsigned database outcome cannot establish terminal accounting.
    unproven_outcomes: BTreeSet<String>,
}

fn authenticate_inventory_records(
    protected_root: &Path,
    records: &[NativeSessionInventoryRecord],
) -> Result<NativeSessionRecordAuthority> {
    let mut authority = NativeSessionRecordAuthority::default();
    if records.is_empty() {
        return Ok(authority);
    }
    for name in [ADMISSION_RECEIPT_DIRECTORY, OUTCOME_RECEIPT_DIRECTORY] {
        let directory = protected_root.join(name);
        match std::fs::symlink_metadata(&directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect native-session receipt directory"),
            Ok(_) => ensure_runtime_evidence_directory(&directory, true)?,
        }
    }
    let root = load_runtime_evidence_product_root(
        &protected_root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH),
    )?;
    let key = root.verifying_key();
    for record in records {
        verify_admission_capture(protected_root, &record.admission)?;
        let admission = read_admission_receipt(protected_root, &record.admission, &key)?;
        let outcome = read_outcome_receipt(protected_root, &record.admission, &key)?;
        if admission.is_none() && outcome.is_none() {
            authority
                .unproven_admissions
                .insert(record.admission.session_nonce.clone());
        }
        if let Some(observed) = &record.outcome {
            match outcome {
                Some(receipt) if receipt.outcome != *observed => {
                    bail!(
                        "native-session database outcome disagrees with its signed supervisor receipt"
                    );
                }
                None => {
                    authority
                        .unproven_outcomes
                        .insert(record.admission.session_nonce.clone());
                }
                Some(_) => {}
            }
        }
    }
    Ok(authority)
}

fn retain_outcome_receipt(
    protected_root: &Path,
    admission: &NativeSessionAdmission,
    outcome: &NativeSessionOutcome,
) -> Result<()> {
    use std::io::Write as _;

    verify_admission_capture(protected_root, admission)?;
    let root = load_runtime_evidence_product_root(
        &protected_root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH),
    )?;
    let receipt = NativeSessionOutcomeReceipt::issue(admission, outcome, &root)?;
    let bytes = bounded_json(&receipt, MAX_OUTCOME_RECEIPT_BYTES)?;
    let directory = protected_root.join(OUTCOME_RECEIPT_DIRECTORY);
    ensure_runtime_evidence_directory(&directory, true)?;
    let path = outcome_receipt_path(protected_root, &admission.session_nonce);
    let mut staged = tempfile::NamedTempFile::new_in(&directory)
        .context("stage private native-session outcome receipt")?;
    staged.write_all(bytes.as_bytes())?;
    staged.as_file().sync_all()?;
    match staged.persist_noclobber(&path) {
        Ok(_) => {}
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = read_outcome_receipt(protected_root, admission, &root.verifying_key())?
                .context("retained native-session outcome disappeared during publication")?;
            if existing.outcome != *outcome {
                bail!("native-session outcome receipt is immutable once observed");
            }
        }
        Err(error) => return Err(error.error).context("publish native-session outcome receipt"),
    }
    // The complete immutable receipt and its directory entry precede the DB
    // update. A crash before publication leaves no authority to recover; a
    // crash afterwards can recover only the authenticated exact observation.
    #[cfg(unix)]
    {
        std::fs::File::open(&directory)?.sync_all()?;
        std::fs::File::open(protected_root)?.sync_all()?;
    }
    Ok(())
}

fn write_observed_outcome(
    tx: &mut Transaction<'_>,
    expected_admission: &NativeSessionAdmission,
    outcome: &NativeSessionOutcome,
) -> Result<()> {
    let rows = tx.query_with_params(
        "SELECT admission_json, outcome_json FROM native_sessions WHERE session_nonce = ?1;",
        &[SqliteValue::Text(
            expected_admission.session_nonce.clone().into(),
        )],
    )?;
    let [row] = rows.as_slice() else {
        bail!("native-session admission disappeared before outcome persistence");
    };
    let [admission, existing] = row.values() else {
        bail!("native-session outcome row shape is invalid");
    };
    let admission: NativeSessionAdmission = parse_json(admission, MAX_ADMISSION_BYTES)?;
    validate_admission(&admission)?;
    if admission != *expected_admission {
        bail!("native-session admission changed before outcome persistence");
    }
    validate_outcome(&admission, outcome)?;
    let json = bounded_json(outcome, MAX_OUTCOME_BYTES)?;
    match existing {
        SqliteValue::Null => {
            tx.execute_with_params(
                "UPDATE native_sessions SET outcome_json = ?1
                 WHERE session_nonce = ?2 AND outcome_json IS NULL;",
                &[
                    SqliteValue::Text(json.into()),
                    SqliteValue::Text(admission.session_nonce.into()),
                ],
            )?;
        }
        value => {
            let existing: NativeSessionOutcome = parse_json(value, MAX_OUTCOME_BYTES)?;
            if existing != *outcome {
                bail!("native-session outcome is immutable once observed");
            }
        }
    }
    Ok(())
}

/// Repair only the missing database projection of already observed outcomes.
/// Call from the mutating fleet reconciliation path, never from inventory
/// inspection. Validate the whole recovery batch before changing any records;
/// concurrent or conflicting terminal observations cannot overwrite each other.
fn recover_retained_outcomes(
    protected_root: &Path,
    connection: &Connection,
    records: &[NativeSessionInventoryRecord],
) -> Result<()> {
    if records.iter().all(|record| record.outcome.is_some()) {
        return Ok(());
    }
    let directory = protected_root.join(OUTCOME_RECEIPT_DIRECTORY);
    match std::fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("inspect retained native-session outcomes"),
        Ok(_) => ensure_runtime_evidence_directory(&directory, true)?,
    }
    let root = load_runtime_evidence_product_root(
        &protected_root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH),
    )?;
    let mut recoveries = Vec::new();
    for record in records.iter().filter(|record| record.outcome.is_none()) {
        if let Some(receipt) =
            read_outcome_receipt(protected_root, &record.admission, &root.verifying_key())?
        {
            verify_admission_capture(protected_root, &record.admission)?;
            recoveries.push((&record.admission, receipt.outcome));
        }
    }
    if recoveries.is_empty() {
        return Ok(());
    }
    retry_snapshot_conflict(|| {
        let mut tx = connection.transaction()?;
        for (admission, outcome) in &recoveries {
            write_observed_outcome(&mut tx, admission, outcome)?;
        }
        check_bounds(&tx)?;
        tx.commit()?;
        Ok(())
    })?;
    tracing::info!(
        event_code = "NATIVE_SESSION_OUTCOMES_RECOVERED",
        recovered_sessions = recoveries.len(),
        "recovered authenticated supervisor observations; unresolved effects retain their original status"
    );
    Ok(())
}

/// An owned supervisor obligation. Dropping this on an ordinary error records
/// only the observations already made. Process death bypasses Drop and leaves
/// the durable admission pending unless an exact signed outcome was already
/// retained. Neither missing process liveness nor elapsed time can resolve it.
pub(crate) struct NativeSessionInventoryGuard {
    connection: Connection,
    protected_root: PathBuf,
    admission: NativeSessionAdmission,
    session_nonce: String,
    process: NativeSessionProcessObservation,
    containment_empty_observed: bool,
    finished: bool,
}

impl NativeSessionInventoryGuard {
    pub(crate) fn admit(
        protected_root: &Path,
        admission: NativeSessionAdmission,
        expected_generation: u64,
    ) -> Result<Self> {
        ensure_runtime_evidence_directory(protected_root, true)?;
        validate_admission(&admission)?;
        let scopes = admission.control_scopes.as_ref().context(
            "new native-session admission requires an explicit complete control-scope census",
        )?;
        let mut expected_scopes =
            BTreeMap::from([(admission.project_root.as_path(), expected_generation)]);
        for scope in scopes {
            expected_scopes.insert(scope.project_root.as_path(), scope.admission_generation);
        }
        verify_admission_capture(protected_root, &admission)?;
        let admission_json = bounded_json(&admission, MAX_ADMISSION_BYTES)?;
        let connection = retry_snapshot_conflict(|| open_inventory(protected_root, true))?
            .context("native-session inventory was not created")?;
        retain_admission_receipt(protected_root, &admission)?;
        // A refused attempt keeps the same decision and timestamp through
        // transaction retries. Its receipt is issued only after this unique
        // insertion commits, so a duplicate/losing admission cannot create a
        // false never-spawned receipt for an already running worker.
        let mut refused_outcome = None;
        let admitted = retry_snapshot_conflict(|| {
            let mut tx = connection.transaction()?;
            // Both the release and its independent operator participate in
            // this same transaction conflict point. Neither can seal a
            // zero-session census while a supervised worker is being admitted.
            let mut admitted = refused_outcome.is_none();
            for (project, expected_generation) in &expected_scopes {
                serialize_project_admission(&mut tx, project)?;
                let drain = latest_drain(&tx, project)?;
                admitted &= drain.as_ref().is_none_or(|drain| !drain.fence_held)
                    && drain.as_ref().map_or(0, |drain| drain.generation) == *expected_generation;
            }
            // A race after identity provisioning must leave a known unspawned
            // outcome, rather than an untracked capture or an apparent worker.
            let outcome = if admitted {
                SqliteValue::Null
            } else {
                let refused = refused_outcome.get_or_insert_with(|| NativeSessionOutcome {
                    observed_at: Utc::now(),
                    kind: NativeSessionOutcomeKind::SupervisionIncomplete,
                    process: NativeSessionProcessObservation::NotSpawned,
                    containment_empty_observed: false,
                    effects: NativeSessionEffectObservation::NotStarted,
                });
                SqliteValue::Text(bounded_json(refused, MAX_OUTCOME_BYTES)?.into())
            };
            tx.execute_with_params(
                "INSERT INTO native_sessions(session_nonce, admission_json, outcome_json)
                 VALUES (?1, ?2, ?3);",
                &[
                    SqliteValue::Text(admission.session_nonce.clone().into()),
                    SqliteValue::Text(admission_json.clone().into()),
                    outcome,
                ],
            )?;
            check_bounds(&tx)?;
            tx.commit()?;
            Ok(admitted)
        })
        .context("persist native-session admission before worker spawn")?;
        if !admitted {
            // No worker was started for this committed row. A crash before
            // receipt persistence leaves its unsigned outcome indeterminate;
            // reconciliation never invents a signature from database counts.
            retain_outcome_receipt(
                protected_root,
                &admission,
                refused_outcome
                    .as_ref()
                    .context("refused native-session admission lost its outcome")?,
            )?;
            bail!(
                "native-session admission crossed a fleet drain fence; no worker was started; retry under the current applied policy"
            );
        }
        Ok(Self {
            connection,
            protected_root: protected_root.to_path_buf(),
            session_nonce: admission.session_nonce.clone(),
            admission,
            process: NativeSessionProcessObservation::NotSpawned,
            containment_empty_observed: false,
            finished: false,
        })
    }

    pub(crate) fn worker_started(&mut self) {
        self.process = NativeSessionProcessObservation::Unproven;
    }

    pub(crate) fn worker_reaped(&mut self) {
        self.process = NativeSessionProcessObservation::WorkerReaped;
    }

    pub(crate) fn containment_empty(&mut self) {
        self.containment_empty_observed = true;
    }

    pub(crate) fn finish(
        &mut self,
        kind: NativeSessionOutcomeKind,
        effects: NativeSessionEffectObservation,
    ) {
        if self.finished {
            return;
        }
        let outcome = NativeSessionOutcome {
            observed_at: Utc::now(),
            kind,
            process: self.process,
            containment_empty_observed: self.containment_empty_observed,
            effects,
        };
        if let Err(error) = self.persist_outcome(&outcome) {
            // Preserve execution error/panic/success. The durable admission
            // remains pending and cannot falsely clear the missing outcome.
            tracing::warn!(session_nonce = %self.session_nonce, %error,
                "native-session outcome could not be persisted; admission remains unresolved");
        }
        self.finished = true;
    }

    fn persist_outcome(&self, outcome: &NativeSessionOutcome) -> Result<()> {
        retain_outcome_receipt(&self.protected_root, &self.admission, outcome)?;
        retry_snapshot_conflict(|| {
            let mut tx = self.connection.transaction()?;
            write_observed_outcome(&mut tx, &self.admission, outcome)?;
            check_bounds(&tx)?;
            tx.commit()?;
            Ok(())
        })
    }
}

impl Drop for NativeSessionInventoryGuard {
    fn drop(&mut self) {
        let effects = if self.process == NativeSessionProcessObservation::NotSpawned {
            NativeSessionEffectObservation::NotStarted
        } else {
            NativeSessionEffectObservation::Unknown
        };
        self.finish(NativeSessionOutcomeKind::SupervisionIncomplete, effects);
    }
}

fn read_records(connection: &Connection) -> Result<Vec<NativeSessionInventoryRecord>> {
    let mut tx = connection.transaction()?;
    let records = read_records_in_transaction(&tx)?;
    tx.commit()?;
    Ok(records)
}

fn read_records_in_transaction(tx: &Transaction<'_>) -> Result<Vec<NativeSessionInventoryRecord>> {
    check_bounds(tx)?;
    let rows = tx.query(&format!(
        "SELECT session_nonce, admission_json, outcome_json FROM native_sessions
         ORDER BY session_nonce ASC LIMIT {};",
        MAX_STORED_SESSIONS + 1
    ))?;
    if rows.len() > MAX_STORED_SESSIONS {
        bail!("native-session inventory exceeds its record bound");
    }
    let records = rows
        .iter()
        .map(|row| {
            let [SqliteValue::Text(nonce), admission, outcome] = row.values() else {
                bail!("native-session inventory row shape is invalid");
            };
            let admission: NativeSessionAdmission = parse_json(admission, MAX_ADMISSION_BYTES)?;
            validate_admission(&admission)?;
            if admission.session_nonce != nonce.as_ref() {
                bail!("native-session inventory nonce does not match its admission");
            }
            let outcome: Option<NativeSessionOutcome> = match outcome {
                SqliteValue::Null => None,
                value => Some(parse_json(value, MAX_OUTCOME_BYTES)?),
            };
            if let Some(outcome) = &outcome {
                validate_outcome(&admission, outcome)?;
            }
            Ok(NativeSessionInventoryRecord { admission, outcome })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(records)
}

fn inventory_root() -> Result<PathBuf> {
    let state_home = runtime_evidence_user_state_home()?;
    let state_home = match state_home.canonicalize() {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => state_home,
        Err(error) => return Err(error).context("resolve native-session user state home"),
    };
    Ok(state_home
        .join(RUNTIME_EVIDENCE_PRODUCT_STATE_DIRECTORY)
        .join(RUNTIME_EVIDENCE_STATE_DIRECTORY))
}

fn project_key(project_root: &Path) -> Result<&str> {
    if !project_root.is_absolute()
        || project_root.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        bail!("native-session drain requires an absolute project identity without traversal");
    }
    project_root
        .to_str()
        .context("native-session drain project must be UTF-8")
}

/// Force a write conflict between admission and fence transitions, even if the
/// storage backend supplies snapshot rather than predicate serializability.
/// Reading different tables then writing disjoint rows would permit write
/// skew: a worker could otherwise be absent from a concurrently sealed census.
fn serialize_project_admission(tx: &mut Transaction<'_>, project_root: &Path) -> Result<()> {
    let key = SqliteValue::Text(project_key(project_root)?.to_owned().into());
    tx.execute_with_params(
        "INSERT OR IGNORE INTO native_session_admission_serialization(project_root, transaction_nonce)
         VALUES (?1, ?2);",
        &[key.clone(), SqliteValue::Text(uuid::Uuid::now_v7().to_string().into())],
    )?;
    tx.execute_with_params(
        "UPDATE native_session_admission_serialization SET transaction_nonce = ?1
         WHERE project_root = ?2;",
        &[
            SqliteValue::Text(uuid::Uuid::now_v7().to_string().into()),
            key,
        ],
    )?;
    Ok(())
}

fn latest_drain(
    tx: &Transaction<'_>,
    project_root: &Path,
) -> Result<Option<StoredNativeSessionDrain>> {
    let key = project_key(project_root)?;
    if tx.query(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'native_session_drains';",
    )?.is_empty() {
        return Ok(None);
    }
    let rows = tx.query_with_params(
        "SELECT drain_id, generation, state_json FROM native_session_drains
         WHERE project_root = ?1 ORDER BY generation DESC LIMIT 1;",
        &[SqliteValue::Text(key.to_owned().into())],
    )?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let [
        SqliteValue::Text(id),
        SqliteValue::Integer(generation),
        json,
    ] = row.values()
    else {
        bail!("native-session drain row shape is invalid");
    };
    let drain: StoredNativeSessionDrain = parse_json(json, MAX_DRAIN_BYTES)?;
    if drain.drain_id != id.as_ref()
        || i64::try_from(drain.generation)? != *generation
        || drain.project_root != project_root
        || drain.generation == 0
        || drain.session_nonces.len() > MAX_STORED_SESSIONS + MAX_IDENTITY_CAPTURES
        || drain.maintenance_hold_ids.len() > MAX_NATIVE_SESSION_MAINTENANCE_HOLDS
        || drain
            .maintenance_hold_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || (!drain.maintenance_hold_ids.is_empty() && !drain.fence_held)
        || drain
            .session_nonces
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        bail!("native-session drain identity or population is inconsistent");
    }
    uuid::Uuid::parse_str(&drain.drain_id)?;
    validate_node_id(&drain.node_id)?;
    validate_zone_id(&drain.zone_id)?;
    for hold_id in &drain.maintenance_hold_ids {
        validate_action_id(hold_id)?;
    }
    for nonce in &drain.session_nonces {
        uuid::Uuid::parse_str(nonce)?;
        if nonce.len() > 64 {
            bail!("native-session drain nonce exceeds its identity bound");
        }
    }
    drain.actions.validate()?;
    Ok(Some(drain))
}

fn require_open_admission(drain: Option<&StoredNativeSessionDrain>) -> Result<u64> {
    if let Some(drain) = drain
        && drain.fence_held
    {
        bail!(
            "native-session admission is fenced by local fleet drain {}",
            drain.drain_id
        );
    }
    Ok(drain.map_or(0, |drain| drain.generation))
}

fn admission_ticket_at(protected_root: &Path, project_root: &Path) -> Result<u64> {
    let Some(connection) = open_inventory(protected_root, false)? else {
        return Ok(0);
    };
    let mut tx = connection.transaction()?;
    let drain = latest_drain(&tx, project_root)?;
    tx.commit()?;
    require_open_admission(drain.as_ref())
}

fn existing_admission_root() -> Result<Option<PathBuf>> {
    let root = inventory_root()?;
    match std::fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect native-session admission fence"),
        Ok(_) => {}
    }
    ensure_runtime_evidence_directory(root.parent().context("missing product state root")?, true)?;
    ensure_runtime_evidence_directory(&root, true)?;
    Ok(Some(root))
}

/// Capture this before the final policy/trust recheck. Admission compares the
/// generation in the same transaction that records the worker obligation.
/// An active fence also makes the existing live observer cancel old workers.
pub(crate) fn native_session_admission_ticket(project_root: &Path) -> Result<u64> {
    let Some(root) = existing_admission_root()? else {
        return Ok(0);
    };
    admission_ticket_at(&root, project_root)
}

/// Reference runtimes execute outside the native worker inventory, but they
/// must still honor its retained admission fences. Check every canonical
/// ancestor in one snapshot so staging or choosing a nested test cannot detach
/// a reference leg from its operator's maintenance hold. This is an admission
/// refusal, not a native-session registration or quiescence certificate.
pub(crate) fn enforce_reference_admission(project_root: &Path) -> Result<()> {
    let Some(root) = existing_admission_root()? else {
        return Ok(());
    };
    enforce_reference_admission_at(&root, project_root)
}

fn enforce_reference_admission_at(protected_root: &Path, project_root: &Path) -> Result<()> {
    // Validate even when the inventory has not been initialized yet.
    project_key(project_root)?;
    let Some(connection) = open_inventory(protected_root, false)? else {
        return Ok(());
    };
    let mut tx = connection.transaction()?;
    for scope in project_root.ancestors() {
        let drain = latest_drain(&tx, scope)?;
        require_open_admission(drain.as_ref())?;
    }
    tx.commit()?;
    Ok(())
}

fn terminal_outcome_observed(
    admission: &NativeSessionAdmission,
    outcome: &NativeSessionOutcome,
) -> bool {
    match (&outcome.process, &outcome.effects) {
        (
            NativeSessionProcessObservation::NotSpawned,
            NativeSessionEffectObservation::NotStarted,
        ) => true,
        (
            NativeSessionProcessObservation::WorkerReaped,
            NativeSessionEffectObservation::FinalLedgerObserved {
                failed_count: 0, ..
            },
        ) => {
            admission.process_spawn_authority_granted == Some(false)
                || (admission.process_spawn_authority_granted == Some(true)
                    && outcome.containment_empty_observed)
        }
        _ => false,
    }
}

fn drain_report(
    drain: &StoredNativeSessionDrain,
    records: &[NativeSessionInventoryRecord],
    authority: &NativeSessionRecordAuthority,
) -> Result<NativeSessionDrainReport> {
    let records: BTreeMap<_, _> = records
        .iter()
        .map(|record| (record.admission.session_nonce.as_str(), record))
        .collect();
    let mut terminal = 0_u64;
    let mut pending = 0_u64;
    let mut indeterminate = 0_u64;
    let mut digest = Sha256::new();
    digest.update(b"franken-node/local-native-drain-population/v1\0");
    digest.update(u64::try_from(drain.session_nonces.len())?.to_be_bytes());
    for nonce in &drain.session_nonces {
        digest.update(u64::try_from(nonce.len())?.to_be_bytes());
        digest.update(nonce.as_bytes());
        let Some(record) = records.get(nonce.as_str()) else {
            // An old signed identity with no supervisor admission is retained
            // as unknown; absence of a PID or elapsed time cannot resolve it.
            indeterminate += 1;
            continue;
        };
        if authority.unproven_admissions.contains(nonce)
            || authority.unproven_outcomes.contains(nonce)
        {
            indeterminate += 1;
            continue;
        }
        let Some(outcome) = &record.outcome else {
            pending += 1;
            continue;
        };
        if terminal_outcome_observed(&record.admission, outcome) {
            terminal += 1
        } else {
            indeterminate += 1
        }
    }
    let checkpoint = NativeSessionDrainCheckpoint {
        applied_actions: drain.actions.clone(),
        session_set_sha256: hex::encode(digest.finalize()),
        admitted_sessions: u64::try_from(drain.session_nonces.len())?,
        terminal_sessions: terminal,
        pending_sessions: pending,
        indeterminate_sessions: indeterminate,
        fence_held: drain.fence_held,
        supervisor_attestation: None,
    };
    checkpoint.validate()?;
    Ok(NativeSessionDrainReport {
        drain_id: drain.drain_id.clone(),
        generation: drain.generation,
        project_root: drain.project_root.clone(),
        node_id: drain.node_id.clone(),
        zone_id: drain.zone_id.clone(),
        session_nonces: drain.session_nonces.clone(),
        checkpoint,
        maintenance_hold_ids: drain.maintenance_hold_ids.clone(),
        fleet_quiescence_certified: false,
    })
}

fn check_drain_owner(drain: &StoredNativeSessionDrain, node_id: &str, zone_id: &str) -> Result<()> {
    if drain.node_id != node_id || drain.zone_id != zone_id {
        bail!("retained native-session drain belongs to a different node/zone identity");
    }
    Ok(())
}

/// A held census cannot become complete by omitting an older admission whose
/// control owners were not captured. An independently authenticated terminal
/// historical outcome can resolve that unknown obligation without rewriting
/// an old census; an unspawned refusal adds no worker obligation either.
fn ensure_held_population_covered(
    drain: &StoredNativeSessionDrain,
    records: &[NativeSessionInventoryRecord],
    authority: &NativeSessionRecordAuthority,
    untracked: &[UntrackedNativeIdentityCapture],
) -> Result<()> {
    if !drain.fence_held {
        // A released census describes its historical cohort only. Later
        // admissions do not retroactively extend or cancel that cohort.
        return Ok(());
    }
    let resolved_outside_census: BTreeSet<_> = records
        .iter()
        .filter(|record| {
            !authority
                .unproven_admissions
                .contains(&record.admission.session_nonce)
                && !authority
                    .unproven_outcomes
                    .contains(&record.admission.session_nonce)
                && record.outcome.as_ref().is_some_and(|outcome| {
                    terminal_outcome_observed(&record.admission, outcome)
                        && (record.admission.control_scopes.is_none()
                            || outcome.process == NativeSessionProcessObservation::NotSpawned)
                })
        })
        .map(|record| record.admission.session_nonce.as_str())
        .collect();
    let required: BTreeSet<_> = records
        .iter()
        .filter(|record| {
            record
                .admission
                .belongs_to_control_scope(&drain.project_root)
                && !resolved_outside_census.contains(record.admission.session_nonce.as_str())
        })
        .map(|record| record.admission.session_nonce.as_str())
        .chain(authority.unproven_admissions.iter().map(String::as_str))
        .chain(
            untracked
                .iter()
                .filter(|capture| !resolved_outside_census.contains(capture.session_nonce.as_str()))
                .map(|capture| capture.session_nonce.as_str()),
        )
        .collect();
    if required.iter().any(|nonce| {
        drain
            .session_nonces
            .binary_search_by(|item| item.as_str().cmp(nonce))
            .is_err()
    }) {
        bail!(
            "native-session drain population changed after the retained snapshot; refusing an older population with unaccounted control-scope obligations"
        );
    }
    Ok(())
}

/// One fleet reconciliation owner per canonical local project. The OS releases
/// this descriptor lock on process exit; retained lock files are never deleted.
/// Guest admission uses the database fence, not this agent-lifetime lock.
pub struct LocalNativeSessionAgentGuard {
    _lock: std::fs::File,
}

/// Serialize the whole apply/drain/heartbeat loop, not just database updates.
/// Without this ownership, a paused agent could apply an old release after a
/// second agent had finished that drain and installed a newer restriction.
pub fn acquire_local_native_session_agent(
    project_root: &Path,
) -> Result<LocalNativeSessionAgentGuard> {
    let project = project_root
        .canonicalize()
        .context("resolve fleet agent project")?;
    let (key_path, _, root) = prepare_runtime_evidence_directories(&project)?;
    load_or_create_runtime_evidence_product_root(&key_path)?;
    acquire_agent_at(&root, &project)
}

#[cfg(any(unix, windows))]
fn agent_lock_path(protected_root: &Path, project_root: &Path) -> Result<PathBuf> {
    let mut hash = Sha256::new();
    hash.update(b"franken-node/local-native-session-agent/v1\0");
    hash.update(project_key(project_root)?.as_bytes());
    Ok(protected_root.join(format!("fleet-agent-{}.lock", hex::encode(hash.finalize()))))
}

#[cfg(unix)]
fn acquire_agent_at(
    protected_root: &Path,
    project_root: &Path,
) -> Result<LocalNativeSessionAgentGuard> {
    let path = agent_lock_path(protected_root, project_root)?;
    create_new_runtime_evidence_private_file(&path, &[])?;
    validate_private_path_if_present(&path)?;
    let observed = std::fs::symlink_metadata(&path)?;
    let file = {
        use rustix::fs::{Mode, OFlags, open};
        use std::os::unix::fs::MetadataExt as _;
        let file = std::fs::File::from(open(
            &path,
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let opened = file.metadata()?;
        if observed.dev() != opened.dev()
            || observed.ino() != opened.ino()
            || opened.nlink() != 1
            || opened.uid() != rustix::process::geteuid().as_raw()
        {
            bail!("fleet agent ownership file identity changed");
        }
        file
    };
    validate_runtime_evidence_private_file_metadata(&path, &file.metadata()?)?;
    file.try_lock().map_err(|error| anyhow::anyhow!(
        "another fleet agent owns this local project, or its ownership lock is unavailable: {error}"
    ))?;
    Ok(LocalNativeSessionAgentGuard { _lock: file })
}

#[cfg(windows)]
fn acquire_agent_at(
    protected_root: &Path,
    project_root: &Path,
) -> Result<LocalNativeSessionAgentGuard> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ_WRITE: u32 = 0x0000_0003;
    for directory in [Some(protected_root), protected_root.parent()]
        .into_iter()
        .flatten()
    {
        if std::fs::symlink_metadata(directory)?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            bail!("fleet agent ownership directory must not be a reparse point");
        }
    }
    let path = agent_lock_path(protected_root, project_root)?;
    create_new_runtime_evidence_private_file(&path, &[])?;
    validate_private_path_if_present(&path)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        // Open the reparse object itself and refuse it below. Disallow delete
        // sharing so another agent cannot replace this pathname while owned.
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .share_mode(FILE_SHARE_READ_WRITE)
        .open(&path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!("fleet agent ownership file must be a regular non-reparse file");
    }
    validate_runtime_evidence_private_file_metadata(&path, &metadata)?;
    file.try_lock().map_err(|error| anyhow::anyhow!(
        "another fleet agent owns this local project, or its ownership lock is unavailable: {error}"
    ))?;
    Ok(LocalNativeSessionAgentGuard { _lock: file })
}

#[cfg(not(any(unix, windows)))]
fn acquire_agent_at(
    _protected_root: &Path,
    _project_root: &Path,
) -> Result<LocalNativeSessionAgentGuard> {
    bail!("local native-session agent ownership is unsupported on this platform")
}

/// Fence admission before applying a changed nonempty fleet snapshot. An
/// initial empty snapshot records a completed checkpoint without cancellation. The
/// population is captured atomically with that fence in the admission store.
/// An unresolved population stays pinned to its exact checkpoint. A fully
/// terminal held population may advance an append-only snapshot without
/// opening admission, making an explicit maintenance resume reachable.
/// Before reconciliation, recover any exact signed supervisor outcomes whose
/// database writes were interrupted. This changes no observation or authority.
pub fn begin_local_native_session_drain(
    project_root: &Path,
    node_id: &str,
    zone_id: &str,
    checkpoint: &FleetApplicationCheckpoint,
    action_history: &[FleetActionRecord],
) -> Result<NativeSessionDrainReport> {
    let project_root = project_root
        .canonicalize()
        .context("resolve native drain project")?;
    let (key_path, _, root) = prepare_runtime_evidence_directories(&project_root)?;
    load_or_create_runtime_evidence_product_root(&key_path)?;
    begin_drain_at(
        &root,
        &project_root,
        node_id,
        zone_id,
        checkpoint,
        action_history,
    )
}

fn begin_drain_at(
    protected_root: &Path,
    project_root: &Path,
    node_id: &str,
    zone_id: &str,
    checkpoint: &FleetApplicationCheckpoint,
    action_history: &[FleetActionRecord],
) -> Result<NativeSessionDrainReport> {
    validate_node_id(node_id)?;
    validate_zone_id(zone_id)?;
    if zone_id == "all" || !valid_digest(&checkpoint.actions_sha256) {
        bail!("native-session drain requires a concrete zone and a valid action checkpoint");
    }
    if fleet_application_checkpoint(action_history, zone_id)? != *checkpoint {
        bail!("native-session drain checkpoint does not match the supplied action history");
    }
    let maintenance_hold_ids: Vec<_> = fleet_native_session_holds(action_history, zone_id)?
        .into_iter()
        .collect();
    let key = project_key(project_root)?;
    // Recover outcomes from this read. The transaction below rereads signed
    // captures against its own admission rows before sealing the census.
    let inventory = retry_snapshot_conflict(|| read_inventory_at(protected_root, None))?;
    let connection = retry_snapshot_conflict(|| open_inventory(protected_root, true))?
        .context("native-session drain inventory was not created")?;
    recover_retained_outcomes(protected_root, &connection, &inventory.records)?;
    let product_root = load_runtime_evidence_product_root(
        &protected_root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH),
    )?;
    retry_snapshot_conflict(|| {
        let mut tx = connection.transaction()?;
        serialize_project_admission(&mut tx, project_root)?;
        let previous = latest_drain(&tx, project_root)?;
        let records = read_records_in_transaction(&tx)?;
        let authority = authenticate_inventory_records(protected_root, &records)?;
        let untracked = untracked_identity_captures_at(protected_root, &records)?;
        if let Some(previous) = &previous {
            check_drain_owner(previous, node_id, zone_id)?;
            if previous.census_signature_hex.is_some() {
                previous.verify_census(&product_root.verifying_key())?;
            }
            ensure_held_population_covered(previous, &records, &authority, &untracked)?;
            let report = drain_report(previous, &records, &authority)?;
            if previous.actions == *checkpoint {
                if previous.maintenance_hold_ids != maintenance_hold_ids {
                    bail!(
                        "native-session maintenance owners disagree with their exact action history"
                    );
                }
                tx.commit()?;
                return Ok(report);
            }
            if previous.fence_held
                && (previous.maintenance_hold_ids.is_empty()
                    || !previous.actions_applied
                    || !report.checkpoint.population_is_terminal())
            {
                tx.commit()?;
                return Ok(report);
            }
            if checkpoint.action_count <= previous.actions.action_count {
                bail!(
                    "native-session drain cannot replace completed action history with a stale or contradictory checkpoint"
                );
            }
            fleet_action_snapshot_prefix(action_history, zone_id, &previous.actions).context(
                "native-session drain history no longer extends the retained completed prefix",
            )?;
        }
        let counts = tx.query("SELECT COUNT(*) FROM native_session_drains;")?;
        let [row] = counts.as_slice() else {
            bail!("invalid native drain count")
        };
        let [SqliteValue::Integer(count)] = row.values() else {
            bail!("invalid native drain count")
        };
        if usize::try_from(*count)? >= MAX_RETAINED_DRAINS {
            bail!(
                "native-session drain history is full; retained obligations will not be discarded"
            );
        }
        let nonces: BTreeSet<_> = records
            .iter()
            .filter(|record| record.admission.belongs_to_control_scope(project_root))
            .map(|record| record.admission.session_nonce.clone())
            .chain(authority.unproven_admissions.iter().cloned())
            .chain(
                untracked
                    .iter()
                    .map(|capture| capture.session_nonce.clone()),
            )
            .chain(
                previous
                    .iter()
                    .filter(|drain| drain.fence_held)
                    .flat_map(|drain| drain.session_nonces.iter().cloned()),
            )
            .collect();
        if nonces.len() > MAX_STORED_SESSIONS + MAX_IDENTITY_CAPTURES {
            bail!("native-session drain population exceeds its retained identity bound");
        }
        let generation = previous
            .as_ref()
            .map_or(0, |drain| drain.generation)
            .checked_add(1)
            .context("native-session drain generation exhausted")?;
        let mut drain = StoredNativeSessionDrain {
            drain_id: uuid::Uuid::now_v7().to_string(),
            generation,
            project_root: project_root.to_path_buf(),
            node_id: node_id.to_owned(),
            zone_id: zone_id.to_owned(),
            session_nonces: if checkpoint.action_count == 0 {
                Vec::new()
            } else {
                nonces.into_iter().collect()
            },
            actions: checkpoint.clone(),
            fence_held: checkpoint.action_count != 0,
            maintenance_hold_ids: maintenance_hold_ids.clone(),
            actions_applied: false,
            census_signature_hex: None,
        };
        drain.seal_census(&product_root)?;
        let report = drain_report(&drain, &records, &authority)?;
        tx.execute_with_params(
            "INSERT INTO native_session_drains(drain_id, project_root, generation, state_json)
             VALUES (?1, ?2, ?3, ?4);",
            &[
                SqliteValue::Text(drain.drain_id.clone().into()),
                SqliteValue::Text(key.to_owned().into()),
                SqliteValue::Integer(i64::try_from(generation)?),
                SqliteValue::Text(bounded_json(&drain, MAX_DRAIN_BYTES)?.into()),
            ],
        )?;
        let sizes = tx.query(
            "SELECT COALESCE(SUM(LENGTH(CAST(state_json AS BLOB))), 0) FROM native_session_drains;",
        )?;
        let [row] = sizes.as_slice() else {
            bail!("invalid native drain byte count")
        };
        let [SqliteValue::Integer(bytes)] = row.values() else {
            bail!("invalid native drain byte count")
        };
        if usize::try_from(*bytes)? > MAX_RESERVED_BYTES {
            bail!("native-session drain history exceeds its retained byte budget");
        }
        tx.commit()?;
        Ok(report)
    })
}

/// Poll the exact retained population after successful action application.
/// Pending/unknown effects and explicit maintenance owners keep the durable
/// fence held across restarts. Only a terminal population with no remaining
/// hold owner permits new admissions under freshly rechecked controls;
/// it certifies neither a distributed barrier nor external rollback.
/// Recover already authenticated observations before evaluating that population;
/// a missing or indeterminate observation never becomes terminal by inference.
pub fn finish_local_native_session_drain(
    project_root: &Path,
    node_id: &str,
    zone_id: &str,
    checkpoint: &FleetApplicationCheckpoint,
) -> Result<NativeSessionDrainReport> {
    let project_root = project_root
        .canonicalize()
        .context("resolve native drain project")?;
    let root = inventory_root()?;
    finish_drain_at(&root, &project_root, node_id, zone_id, checkpoint)
}

fn finish_drain_at(
    protected_root: &Path,
    project_root: &Path,
    node_id: &str,
    zone_id: &str,
    checkpoint: &FleetApplicationCheckpoint,
) -> Result<NativeSessionDrainReport> {
    // Validate retained signed identities before consuming either database
    // outcomes or their independently authenticated crash-recovery receipts.
    let inventory = retry_snapshot_conflict(|| read_inventory_at(protected_root, None))?;
    let connection =
        open_inventory(protected_root, false)?.context("native-session drain store is absent")?;
    recover_retained_outcomes(protected_root, &connection, &inventory.records)?;
    let product_root = load_runtime_evidence_product_root(
        &protected_root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH),
    )?;
    retry_snapshot_conflict(|| {
        let mut tx = connection.transaction()?;
        serialize_project_admission(&mut tx, project_root)?;
        let mut drain =
            latest_drain(&tx, project_root)?.context("no retained native-session drain")?;
        check_drain_owner(&drain, node_id, zone_id)?;
        if drain.census_signature_hex.is_some() {
            drain.verify_census(&product_root.verifying_key())?;
        }
        if drain.actions != *checkpoint {
            bail!("native-session drain completion requires its exact retained action checkpoint");
        }
        let records = read_records_in_transaction(&tx)?;
        let authority = authenticate_inventory_records(protected_root, &records)?;
        let untracked = untracked_identity_captures_at(protected_root, &records)?;
        ensure_held_population_covered(&drain, &records, &authority, &untracked)?;
        let report = drain_report(&drain, &records, &authority)?;
        let mut changed = !drain.actions_applied;
        drain.actions_applied = true;
        if drain.fence_held
            && report.checkpoint.population_is_terminal()
            && drain.maintenance_hold_ids.is_empty()
        {
            drain.fence_held = false;
            changed = true;
        }
        if changed {
            tx.execute_with_params(
                "UPDATE native_session_drains SET state_json = ?1 WHERE drain_id = ?2;",
                &[
                    SqliteValue::Text(bounded_json(&drain, MAX_DRAIN_BYTES)?.into()),
                    SqliteValue::Text(drain.drain_id.clone().into()),
                ],
            )?;
        }
        let report = drain_report(&drain, &records, &authority)?;
        tx.commit()?;
        Ok(report)
    })
}

/// Produce a fresh source-free supervisor observation from the retained
/// inventory, after rechecking the exact action snapshot and every signed
/// admission/outcome. Caller-provided counts are never signing inputs.
///
/// This authenticates local accounting only. A released fence allows later
/// admissions, so the result cannot certify ongoing fleet quiescence.
pub fn attest_local_native_session_drain(
    project_root: &Path,
    node_id: &str,
    zone_id: &str,
    checkpoint: &FleetApplicationCheckpoint,
) -> Result<NativeSessionDrainReport> {
    let project_root = project_root
        .canonicalize()
        .context("resolve native drain attestation project")?;
    let root = inventory_root()?;
    attest_drain_at(&root, &project_root, node_id, zone_id, checkpoint)
}

fn attest_drain_at(
    protected_root: &Path,
    project_root: &Path,
    node_id: &str,
    zone_id: &str,
    checkpoint: &FleetApplicationCheckpoint,
) -> Result<NativeSessionDrainReport> {
    use ed25519_dalek::Signer as _;

    retry_snapshot_conflict(|| read_inventory_at(protected_root, None))?;
    let connection = open_inventory(protected_root, false)?
        .context("native-session drain attestation requires its retained inventory")?;
    let root = load_runtime_evidence_product_root(
        &protected_root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH),
    )?;
    retry_snapshot_conflict(|| {
        let mut tx = connection.transaction()?;
        // Serialize with both admission and fence transitions. Do not freshly
        // sign an earlier read that can omit a newly committed session.
        serialize_project_admission(&mut tx, project_root)?;
        let drain = latest_drain(&tx, project_root)?
            .context("native-session drain attestation requires a retained drain")?;
        check_drain_owner(&drain, node_id, zone_id)?;
        drain.verify_census(&root.verifying_key())?;
        if drain.actions != *checkpoint {
            bail!("native-session drain attestation requires its exact retained action checkpoint");
        }
        if !drain.actions_applied {
            bail!(
                "native-session drain attestation requires confirmed application of its exact retained actions"
            );
        }
        let records = read_records_in_transaction(&tx)?;
        let authority = authenticate_inventory_records(protected_root, &records)?;
        let untracked = untracked_identity_captures_at(protected_root, &records)?;
        ensure_held_population_covered(&drain, &records, &authority, &untracked)?;
        let mut report = drain_report(&drain, &records, &authority)?;
        let project = project_key(project_root)?;
        let mut digest = Sha256::new();
        digest.update(b"franken-node/native-session-drain-project/v1\0");
        digest.update(u64::try_from(project.len())?.to_be_bytes());
        digest.update(project.as_bytes());
        let mut attestation = NativeSessionDrainAttestation {
            schema_version: NATIVE_SESSION_DRAIN_ATTESTATION_SCHEMA.to_owned(),
            node_id: drain.node_id.clone(),
            zone_id: drain.zone_id.clone(),
            drain_id: drain.drain_id.clone(),
            generation: drain.generation,
            project_root_sha256: hex::encode(digest.finalize()),
            observed_at: Utc::now(),
            product_root_key_id: format!(
                "ed25519:{}",
                hex::encode(root.verifying_key().as_bytes())
            ),
            checkpoint_sha256: report.checkpoint.observation_sha256()?,
            signature_hex: String::new(),
        };
        attestation.signature_hex =
            hex::encode(root.sign(&attestation.signing_payload()?).to_bytes());
        attestation.verify(&report.checkpoint, node_id, zone_id, &root.verifying_key())?;
        report.checkpoint.supervisor_attestation = Some(attestation);
        tx.commit()?;
        Ok(report)
    })
}

/// Read this user's protected native-session population. This is a local,
/// bounded observation, never a fleet acknowledgement or quiescence proof.
/// Existing project paths are canonicalized; a missing old absolute path can
/// still select retained sessions after the project has been renamed.
pub fn read_local_native_session_inventory(
    project_root: Option<&Path>,
) -> Result<NativeSessionInventoryReport> {
    let state_home = runtime_evidence_user_state_home()?;
    let state_home = match state_home.canonicalize() {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => state_home,
        Err(error) => return Err(error).context("resolve native-session user state home"),
    };
    let protected_root = state_home
        .join(RUNTIME_EVIDENCE_PRODUCT_STATE_DIRECTORY)
        .join(RUNTIME_EVIDENCE_STATE_DIRECTORY);
    read_inventory_at(&protected_root, project_root)
}

/// Match retained signed captures against the exact transaction's rows. A
/// pre-lock inventory snapshot must not hide a newly untracked identity when
/// sealing or signing a population.
fn untracked_identity_captures_at(
    protected_root: &Path,
    records: &[NativeSessionInventoryRecord],
) -> Result<Vec<UntrackedNativeIdentityCapture>> {
    let tracked: BTreeMap<_, _> = records
        .iter()
        .map(|record| (record.admission.session_nonce.clone(), &record.admission))
        .collect();
    let mut matched = BTreeSet::new();
    let mut untracked = Vec::new();
    let capture_directory = protected_root.join(RUNTIME_EVIDENCE_CAPTURE_DIR_RELATIVE_PATH);
    let captures_present = match std::fs::symlink_metadata(&capture_directory) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error).context("inspect native identity capture directory"),
    };
    if captures_present {
        ensure_runtime_evidence_directory(&capture_directory, true)?;
        ensure_runtime_evidence_directory(&protected_root.join("keys"), true)?;
        let product_root = load_runtime_evidence_product_root(
            &protected_root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH),
        )?;
        let mut captures = std::fs::read_dir(&capture_directory)?;
        for index in 0..=MAX_IDENTITY_CAPTURES {
            let Some(entry) = captures.next() else {
                break;
            };
            if index == MAX_IDENTITY_CAPTURES {
                bail!(
                    "native identity capture inventory exceeds its bound; refusing incomplete coverage"
                );
            }
            let path = entry?.path();
            let bytes = read_runtime_evidence_private_file(&path, 64 * 1024)?;
            let capture: RuntimeEvidenceIdentityCapture = serde_json::from_slice(&bytes)?;
            capture.verify_with_product_root(&product_root.verifying_key())?;
            if let Some(admission) = tracked.get(&capture.session_nonce) {
                if admission.identity_capture_path != path
                    || admission.product_root_key_id != capture.product_root_key_id
                    || admission.security_epoch
                        != capture
                            .evidence_verification_identity
                            .key_provenance
                            .activation_epoch
                            .as_u64()
                    || !matched.insert(capture.session_nonce)
                {
                    bail!("native-session inventory and captured identity disagree");
                }
            } else {
                untracked.push(UntrackedNativeIdentityCapture {
                    session_nonce: capture.session_nonce,
                    product_root_key_id: capture.product_root_key_id,
                    identity_capture_path: path,
                });
            }
        }
    }
    if matched.len() != records.len() {
        bail!("native-session inventory is missing a retained identity capture");
    }
    untracked.sort_by(|left, right| left.session_nonce.cmp(&right.session_nonce));
    Ok(untracked)
}

fn read_inventory_at(
    protected_root: &Path,
    project_root: Option<&Path>,
) -> Result<NativeSessionInventoryReport> {
    let project_root = project_root
        .map(|path| match path.canonicalize() {
            Ok(path) => Ok(path),
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && path.is_absolute()
                    && !path
                        .components()
                        .any(|part| matches!(part, std::path::Component::ParentDir)) =>
            {
                Ok(path.to_path_buf())
            }
            Err(error) => Err(error).context("resolve native-session project filter"),
        })
        .transpose()?;
    let mut report = NativeSessionInventoryReport {
        schema_version: INVENTORY_SCHEMA.to_string(),
        scope: "local_supervisor_observation".to_string(),
        coverage: "sessions_admitted_by_inventory_aware_supervisors_only".to_string(),
        quiescence_certified: false,
        database_path: protected_root.join(INVENTORY_FILE),
        store_present: false,
        project_root,
        total_stored_sessions: 0,
        pending_sessions: 0,
        terminal_sessions: 0,
        unproven_process_sessions: 0,
        unknown_effect_sessions: 0,
        records: Vec::new(),
        untracked_identity_captures: Vec::new(),
    };
    match std::fs::symlink_metadata(protected_root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(report),
        Err(error) => return Err(error).context("inspect native-session protected state root"),
        Ok(_) => {}
    }
    // Check each protected component, not just a leaf beneath a symlink.
    if let Some(product_root) = protected_root.parent() {
        ensure_runtime_evidence_directory(product_root, true)?;
    }
    ensure_runtime_evidence_directory(protected_root, true)?;
    let records = if let Some(connection) = open_inventory(protected_root, false)? {
        report.store_present = true;
        read_records(&connection)?
    } else {
        Vec::new()
    };
    report.total_stored_sessions = records.len();
    report.untracked_identity_captures = untracked_identity_captures_at(protected_root, &records)?;
    for record in records {
        if report
            .project_root
            .as_ref()
            .is_some_and(|project| !record.admission.belongs_to_control_scope(project))
        {
            continue;
        }
        match record.outcome.as_ref() {
            None => {
                report.pending_sessions += 1;
                report.unknown_effect_sessions += 1;
                report.unproven_process_sessions += 1;
            }
            Some(outcome) => {
                if outcome.process == NativeSessionProcessObservation::WorkerReaped {
                    report.terminal_sessions += 1;
                } else if outcome.process == NativeSessionProcessObservation::Unproven {
                    report.unproven_process_sessions += 1;
                }
                if outcome.effects.unknown() {
                    report.unknown_effect_sessions += 1;
                }
            }
        }
        report.records.push(record);
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frankenengine_engine::{
        evidence_ledger::RuntimeEvidenceAuthority, security_epoch::SecurityEpoch,
        signature_preimage::SigningKey,
    };

    fn fixture(root: &Path, marker: u8) -> NativeSessionAdmission {
        ensure_runtime_evidence_directory(root, true).unwrap();
        let keys = root.join("keys");
        let captures = root.join(RUNTIME_EVIDENCE_CAPTURE_DIR_RELATIVE_PATH);
        ensure_runtime_evidence_directory(&keys, true).unwrap();
        ensure_runtime_evidence_directory(&captures, true).unwrap();
        let root_key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
        create_new_runtime_evidence_private_file(
            &root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH),
            &root_key.to_bytes(),
        )
        .unwrap();
        let authority = RuntimeEvidenceAuthority::from_signing_key(
            format!("inventory-test-{marker}"),
            SigningKey::from_bytes([marker; 32]).unwrap(),
            SecurityEpoch::from_raw(3),
            1,
            None,
        )
        .unwrap();
        let nonce = uuid::Uuid::now_v7().to_string();
        let capture = RuntimeEvidenceIdentityCapture::issue(
            &nonce,
            authority.verification_identity(),
            &root_key,
        )
        .unwrap();
        let capture_path = captures.join(format!(
            "{}.json",
            capture
                .evidence_verification_identity
                .verification_key
                .to_hex()
        ));
        create_new_runtime_evidence_private_file(
            &capture_path,
            &serde_json::to_vec(&capture).unwrap(),
        )
        .unwrap();
        NativeSessionAdmission {
            session_nonce: nonce,
            product_root_key_id: capture.product_root_key_id,
            identity_capture_path: capture_path,
            security_epoch: 3,
            admitted_at: Utc::now(),
            project_root: root.parent().unwrap().join("old-project"),
            entrypoint: root.parent().unwrap().join("old-project/index.js"),
            dependency_ids: vec!["package-a".to_string()],
            configured_node_id: None,
            fleet_zone_id: None,
            fleet_policy_sha256: None,
            process_spawn_authority_granted: Some(false),
            control_scopes: Some(Vec::new()),
        }
    }

    fn operator_fixture(
        root: &Path,
        marker: u8,
        operator: &Path,
        generation: u64,
    ) -> NativeSessionAdmission {
        let mut admission = fixture(root, marker);
        admission.control_scopes = Some(vec![NativeSessionControlScope {
            project_root: operator.to_path_buf(),
            admission_generation: generation,
            fleet_policy_sha256: None,
        }]);
        admission
    }

    #[test]
    fn operator_scope_retains_external_sessions_and_independent_hold_owners() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let operator = temp.path().join("operator-project");
        let admission = operator_fixture(&root, 101, &operator, 0);
        let project = admission.project_root.clone();
        let nonce = admission.session_nonce.clone();
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        guard.worker_started();
        for scope in [&operator, &project] {
            let retained = read_inventory_at(&root, Some(scope)).unwrap();
            assert_eq!(retained.pending_sessions, 1);
            assert_eq!(retained.records[0].admission, admission);
            assert!(!retained.quiescence_certified);
        }
        assert!(
            read_inventory_at(&root, Some(&temp.path().join("unrelated")))
                .unwrap()
                .records
                .is_empty()
        );
        let mut history = vec![maintenance_action("held", None)];
        let checkpoint = fleet_application_checkpoint(&history, "prod").unwrap();
        for (scope, node) in [(&operator, "operator-node"), (&project, "release-node")] {
            let pending =
                super::begin_drain_at(&root, scope, node, "prod", &checkpoint, &history).unwrap();
            assert_eq!(pending.session_nonces, vec![nonce.clone()]);
            assert_eq!(pending.checkpoint.pending_sessions, 1);
            assert!(admission_ticket_at(&root, scope).is_err());
        }
        // Preserve the actual signed final observation but lose its database
        // projection; either owner's reconciliation must recover the same nonce.
        guard.worker_reaped();
        abandon_after_receipt(&root, guard, &terminal_outcome());
        for (scope, node) in [(&operator, "operator-node"), (&project, "release-node")] {
            let held = finish_drain_at(&root, scope, node, "prod", &checkpoint).unwrap();
            assert_eq!(held.checkpoint.terminal_sessions, 1);
            assert_eq!(held.checkpoint.pending_sessions, 0);
            assert!(held.checkpoint.fence_held);
            let signed = attest_drain_at(&root, scope, node, "prod", &checkpoint).unwrap();
            assert_eq!(signed.session_nonces, vec![nonce.clone()]);
            assert!(signed.checkpoint.supervisor_attestation.is_some());
        }
        history.push(maintenance_action("resumed", Some("held")));
        let resumed_checkpoint = fleet_application_checkpoint(&history, "prod").unwrap();
        super::begin_drain_at(
            &root,
            &operator,
            "operator-node",
            "prod",
            &resumed_checkpoint,
            &history,
        )
        .unwrap();
        let operator_resumed = finish_drain_at(
            &root,
            &operator,
            "operator-node",
            "prod",
            &resumed_checkpoint,
        )
        .unwrap();
        assert!(operator_resumed.checkpoint.is_complete());
        assert!(admission_ticket_at(&root, &project).is_err());
        let refused = operator_fixture(&root, 102, &operator, operator_resumed.generation);
        assert!(NativeSessionInventoryGuard::admit(&root, refused, 1).is_err());
        super::begin_drain_at(
            &root,
            &project,
            "release-node",
            "prod",
            &resumed_checkpoint,
            &history,
        )
        .unwrap();
        let release_resumed =
            finish_drain_at(&root, &project, "release-node", "prod", &resumed_checkpoint).unwrap();
        assert!(release_resumed.checkpoint.is_complete());
        let fresh = operator_fixture(&root, 103, &operator, operator_resumed.generation);
        let admitted =
            NativeSessionInventoryGuard::admit(&root, fresh, release_resumed.generation).unwrap();
        drop(admitted);
        assert_eq!(
            read_inventory_at(&root, Some(&operator))
                .unwrap()
                .records
                .len(),
            3
        );
        assert_eq!(
            read_inventory_at(&root, Some(&project))
                .unwrap()
                .records
                .len(),
            3
        );
    }

    #[test]
    fn operator_scope_generation_change_refuses_stale_preflight_after_release() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let operator = temp.path().join("operator-project");
        // The ordinary session belongs only to its own release project.
        drop(NativeSessionInventoryGuard::admit(&root, fixture(&root, 104), 0).unwrap());
        let old_ticket = admission_ticket_at(&root, &operator).unwrap();
        assert_eq!(old_ticket, 0);
        let drain = begin_drain_at(&root, &operator, "node-a", "prod", &actions(1)).unwrap();
        assert_eq!(drain.checkpoint.admitted_sessions, 0);
        let drained = finish_drain_at(&root, &operator, "node-a", "prod", &actions(1)).unwrap();
        assert!(drained.checkpoint.is_complete());
        let stale = operator_fixture(&root, 105, &operator, old_ticket);
        let error = NativeSessionInventoryGuard::admit(&root, stale.clone(), 0)
            .err()
            .expect("completed operator drain must invalidate the older ticket");
        assert!(format!("{error:#}").contains("drain fence"));
        let key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]).verifying_key();
        let outcome = read_outcome_receipt(&root, &stale, &key).unwrap().unwrap();
        assert_eq!(
            outcome.outcome.process,
            NativeSessionProcessObservation::NotSpawned
        );
        assert_eq!(
            outcome.outcome.effects,
            NativeSessionEffectObservation::NotStarted
        );
        let fresh = operator_fixture(&root, 106, &operator, drained.generation);
        let mut guard = NativeSessionInventoryGuard::admit(&root, fresh, 0).unwrap();
        guard.worker_started();
        let next = begin_drain_at(&root, &operator, "node-a", "prod", &actions(2)).unwrap();
        assert_eq!(next.checkpoint.admitted_sessions, 2);
        assert_eq!(next.checkpoint.terminal_sessions, 1);
        assert_eq!(next.checkpoint.pending_sessions, 1);
        guard.worker_reaped();
        guard.finish(
            NativeSessionOutcomeKind::ControlStopped,
            successful_ledger_observation(),
        );
        assert!(
            finish_drain_at(&root, &operator, "node-a", "prod", &actions(2))
                .unwrap()
                .checkpoint
                .is_complete()
        );
    }

    #[test]
    fn operator_scope_tampering_cannot_reuse_the_signed_admission() {
        for mutation in 0..5 {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let operator = temp.path().join("operator-project");
            let mut admission = operator_fixture(&root, 107, &operator, 0);
            let mut guard =
                NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            guard.worker_started();
            guard.finished = true;
            drop(guard);
            begin_drain_at(&root, &operator, "node-a", "prod", &actions(1)).unwrap();
            finish_drain_at(&root, &operator, "node-a", "prod", &actions(1)).unwrap();
            match mutation {
                0 => admission.control_scopes = None,
                1 => admission.control_scopes = Some(Vec::new()),
                2 => {
                    admission.control_scopes.as_mut().unwrap()[0].project_root =
                        temp.path().join("other-operator")
                }
                3 => admission.control_scopes.as_mut().unwrap()[0].admission_generation = 1,
                _ => {
                    admission.control_scopes.as_mut().unwrap()[0].fleet_policy_sha256 =
                        Some("b".repeat(64))
                }
            }
            let connection = open_inventory(&root, false).unwrap().unwrap();
            let mut tx = connection.transaction().unwrap();
            tx.execute_with_params(
                "UPDATE native_sessions SET admission_json = ?1 WHERE session_nonce = ?2;",
                &[
                    SqliteValue::Text(serde_json::to_string(&admission).unwrap().into()),
                    SqliteValue::Text(admission.session_nonce.into()),
                ],
            )
            .unwrap();
            tx.commit().unwrap();
            assert!(finish_drain_at(&root, &operator, "node-a", "prod", &actions(1)).is_err());
            assert!(attest_drain_at(&root, &operator, "node-a", "prod", &actions(1)).is_err());
            assert!(admission_ticket_at(&root, &operator).is_err());
        }
    }

    #[test]
    fn historical_scope_absence_retains_obligations_and_cannot_release_an_older_census() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let operator = temp.path().join("operator-project");
        drop(NativeSessionInventoryGuard::admit(&root, fixture(&root, 108), 0).unwrap());
        let history = vec![maintenance_action("old-held-census", None)];
        let checkpoint = fleet_application_checkpoint(&history, "prod").unwrap();
        super::begin_drain_at(&root, &operator, "node-a", "prod", &checkpoint, &history).unwrap();
        let original = finish_drain_at(&root, &operator, "node-a", "prod", &checkpoint).unwrap();
        assert_eq!(original.checkpoint.admitted_sessions, 0);
        let mut historical = fixture(&root, 109);
        historical.control_scopes = None;
        let bytes = serde_json::to_vec(&historical).unwrap();
        assert!(
            !serde_json::from_slice::<serde_json::Value>(&bytes)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("control_scopes")
        );
        retain_admission_receipt(&root, &historical).unwrap();
        let connection = open_inventory(&root, false).unwrap().unwrap();
        let mut tx = connection.transaction().unwrap();
        tx.execute_with_params(
            "INSERT INTO native_sessions(session_nonce, admission_json, outcome_json) VALUES (?1, ?2, NULL);",
            &[
                SqliteValue::Text(historical.session_nonce.clone().into()),
                SqliteValue::Text(String::from_utf8(bytes).unwrap().into()),
            ],
        ).unwrap();
        tx.commit().unwrap();
        let pending = read_inventory_at(&root, Some(&operator)).unwrap();
        assert_eq!(pending.pending_sessions, 1);
        assert_eq!(
            pending.records[0].admission.session_nonce,
            historical.session_nonce
        );
        assert!(
            super::begin_drain_at(&root, &operator, "node-a", "prod", &checkpoint, &history)
                .is_err()
        );
        assert!(finish_drain_at(&root, &operator, "node-a", "prod", &checkpoint).is_err());
        assert!(attest_drain_at(&root, &operator, "node-a", "prod", &checkpoint).is_err());
        assert!(admission_ticket_at(&root, &operator).is_err());
        // The old full-admission signature remains valid, but cannot be
        // upgraded to an assertion that it had no additional operator owner.
        let key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]).verifying_key();
        let receipt = read_admission_receipt(&root, &historical, &key)
            .unwrap()
            .unwrap();
        let mut falsely_completed_census = historical.clone();
        falsely_completed_census.control_scopes = Some(Vec::new());
        assert!(receipt.verify(&falsely_completed_census, &key).is_err());
        retain_outcome_receipt(&root, &historical, &terminal_outcome()).unwrap();
        // A genuine terminal observation resolves the historical unknown;
        // the old cohort and its explicit maintenance hold are preserved.
        let recovered = finish_drain_at(&root, &operator, "node-a", "prod", &checkpoint).unwrap();
        assert_eq!(recovered.session_nonces, original.session_nonces);
        assert!(recovered.checkpoint.fence_held);
        assert!(attest_drain_at(&root, &operator, "node-a", "prod", &checkpoint).is_ok());
        assert!(!recovered.fleet_quiescence_certified);
    }

    #[test]
    fn new_admissions_require_a_bounded_explicit_control_scope_census() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let operator = temp.path().join("operator");
        let admission = operator_fixture(&root, 110, &operator, 0);
        for invalid in [
            PathBuf::from("relative"),
            operator.join("../other"),
            admission.project_root.clone(),
            PathBuf::from(format!("/{}", "x".repeat(4096))),
        ] {
            let mut changed = admission.clone();
            changed.control_scopes.as_mut().unwrap()[0].project_root = invalid;
            assert!(validate_admission(&changed).is_err());
        }
        let mut repeated = admission.clone();
        repeated
            .control_scopes
            .as_mut()
            .unwrap()
            .push(admission.control_scopes.as_ref().unwrap()[0].clone());
        assert!(validate_admission(&repeated).is_err());
        let mut bad_policy = admission.clone();
        bad_policy.control_scopes.as_mut().unwrap()[0].fleet_policy_sha256 = Some("invalid".into());
        assert!(validate_admission(&bad_policy).is_err());
        let mut missing = admission;
        missing.control_scopes = None;
        validate_admission(&missing).unwrap(); // historical parsing remains possible
        let error = NativeSessionInventoryGuard::admit(&root, missing, 0)
            .err()
            .unwrap();
        assert!(error.to_string().contains("complete control-scope census"));
    }

    #[test]
    fn simultaneous_operator_scope_admission_and_fence_retain_the_external_worker() {
        for _ in 0..4 {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let operator = temp.path().join("operator-project");
            let admission = operator_fixture(&root, 111, &operator, 0);
            let nonce = admission.session_nonce.clone();
            open_inventory(&root, true).unwrap();
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let start = std::sync::Arc::clone(&barrier);
            let worker_root = root.clone();
            let worker = std::thread::spawn(move || {
                start.wait();
                match NativeSessionInventoryGuard::admit(&worker_root, admission, 0) {
                    Ok(guard) => drop(guard),
                    Err(error) => assert!(format!("{error:#}").contains("drain fence")),
                }
            });
            barrier.wait();
            let started = begin_drain_at(&root, &operator, "node-a", "prod", &actions(1)).unwrap();
            worker.join().unwrap();
            assert!(started.session_nonces.contains(&nonce));
            let finished =
                finish_drain_at(&root, &operator, "node-a", "prod", &actions(1)).unwrap();
            assert!(finished.checkpoint.is_complete());
            assert_eq!(finished.checkpoint.admitted_sessions, 1);
            assert_eq!(finished.checkpoint.terminal_sessions, 1);
            assert_eq!(
                finished.checkpoint.session_set_sha256,
                started.checkpoint.session_set_sha256
            );
        }
    }

    #[test]
    fn supported_large_trust_identity_set_fits_without_truncation() {
        use crate::ops::engine_dispatcher::RunTrustRequirements;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let mut admission = fixture(&root, 28);
        // Exercise the existing 81,920-identity limit with 2,048,000 raw
        // bytes. Quotes are valid identities under that contract and expand
        // in JSON, so even an arbitrary 3MiB accounting cap would regress it.
        let identities: Vec<String> = (0..81_920)
            .map(|index| format!("dep-{index:05}-{}", "\"".repeat(15)))
            .collect();
        assert_eq!(identities.iter().map(String::len).sum::<usize>(), 2_048_000);
        RunTrustRequirements::new(&identities, &[], false)
            .expect("identity set is supported by the existing execution trust contract");
        admission.dependency_ids = identities;
        let encoded = bounded_json(&admission, MAX_ADMISSION_BYTES).unwrap();
        assert!(encoded.len() > 3 * 1024 * 1024);
        assert!(encoded.len() <= NATIVE_SESSION_MAX_REQUEST_BYTES);
        let decoded: NativeSessionAdmission = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, admission);
    }

    #[test]
    fn maximum_wal_prefix_and_bounded_control_detail_fit_complete_outcome() {
        use crate::ops::engine_dispatcher::{
            NativeEffectWalEntry, NativeRunControlKind, NativeRunControlTrigger,
        };
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let admission = fixture(&root, 29);
        // Each returned effect consumed admission+completion events. The
        // final unmatched call consumes only its admission: 2,047 of 2,048
        // allowed events, with canonical hashes and a real provider kind.
        let effect_count = NATIVE_SESSION_MAX_EFFECT_WAL_EVENTS / 2;
        let entries = (0..effect_count)
            .map(|index| NativeEffectWalEntry {
                sequence: u64::try_from(index).unwrap(),
                effect_kind: "network_egress".to_string(),
                request_hash: format!("sha256:{index:064x}"),
                state: if index + 1 == effect_count {
                    NativeEffectWalState::InterruptedIndeterminate
                } else {
                    NativeEffectWalState::ProviderReturned
                },
            })
            .collect();
        let evidence = NativeEffectInterruptionEvidence {
            schema_version: NATIVE_EFFECT_INTERRUPTION_EVIDENCE_SCHEMA.to_string(),
            session_nonce: admission.session_nonce.clone(),
            terminal_state: "control_indeterminate".to_string(),
            replay_certified: false,
            journal_complete: true,
            journal_event_cap: NATIVE_SESSION_MAX_EFFECT_WAL_EVENTS,
            completed_effect_count: effect_count - 1,
            interrupted_effect_count: 1,
            entries,
            protocol_error: None,
            control_trigger: Some(NativeRunControlTrigger {
                kind: NativeRunControlKind::ExecutionTrust,
                detail: "x".repeat(NATIVE_SESSION_MAX_DIAGNOSTIC_BYTES),
            }),
        };
        let outcome = NativeSessionOutcome {
            observed_at: Utc::now(),
            kind: NativeSessionOutcomeKind::Interrupted,
            process: NativeSessionProcessObservation::WorkerReaped,
            containment_empty_observed: false,
            effects: NativeSessionEffectObservation::Interrupted {
                evidence: Box::new(evidence),
            },
        };
        validate_outcome(&admission, &outcome).unwrap();
        let encoded = bounded_json(&outcome, MAX_OUTCOME_BYTES).unwrap();
        assert!(
            encoded.len() > 1024 * 1024,
            "old inventory ceiling would lose this record"
        );
        let decoded: NativeSessionOutcome = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, outcome);
        assert_eq!(MAX_RESERVED_BYTES, 256 * 1024 * 1024);
    }

    #[test]
    fn pending_admission_survives_reopening_without_liveness_inference() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let admission = fixture(&root, 21);
        let nonce = admission.session_nonce.clone();
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        guard.worker_started();
        // Close the connection without recording an outcome. This exercises
        // reopening durable pending state, not a claim of SIGKILL coverage.
        guard.finished = true;
        drop(guard);
        let report = read_inventory_at(&root, None).unwrap();
        assert_eq!(report.pending_sessions, 1);
        assert_eq!(report.unknown_effect_sessions, 1);
        assert_eq!(report.terminal_sessions, 0);
        assert_eq!(report.records[0].admission.session_nonce, nonce);
        assert!(report.records[0].outcome.is_none());
        assert!(!report.quiescence_certified);
    }

    #[test]
    fn reaped_worker_preserves_unknown_effects_and_outcome_cannot_be_rewritten() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let mut guard = NativeSessionInventoryGuard::admit(&root, fixture(&root, 22), 0).unwrap();
        guard.worker_started();
        guard.worker_reaped();
        guard.finish(
            NativeSessionOutcomeKind::Completed,
            NativeSessionEffectObservation::Unknown,
        );
        let report = read_inventory_at(&root, None).unwrap();
        assert_eq!(report.terminal_sessions, 1);
        assert_eq!(report.unknown_effect_sessions, 1);
        let outcome = report.records[0].outcome.as_ref().unwrap();
        assert!(!outcome.containment_empty_observed);
        guard.persist_outcome(outcome).unwrap();
        let mut forged = outcome.clone();
        forged.kind = NativeSessionOutcomeKind::ExecutionFailed;
        assert!(
            guard
                .persist_outcome(&forged)
                .unwrap_err()
                .to_string()
                .contains("immutable")
        );
        assert_eq!(
            read_inventory_at(&root, None).unwrap().records,
            report.records
        );
    }

    fn final_ledger_observation() -> NativeSessionEffectObservation {
        // This fixture exercises inventory retention, not signature validation.
        // Only the dispatcher may construct this summary from a verified ledger.
        NativeSessionEffectObservation::FinalLedgerObserved {
            effect_count: 3,
            allowed_count: 1,
            denied_count: 1,
            failed_count: 1,
            chain_head_hash: format!("sha256:{}", "a".repeat(64)),
            ledger_sha256: "b".repeat(64),
        }
    }

    fn actions(count: u64) -> FleetApplicationCheckpoint {
        fleet_application_checkpoint(&action_history(count), "prod").unwrap()
    }

    #[test]
    fn drain_serialization_preserves_the_entire_existing_inventory_capacity() {
        let population = MAX_STORED_SESSIONS + MAX_IDENTITY_CAPTURES;
        let drain = StoredNativeSessionDrain {
            drain_id: uuid::Uuid::now_v7().to_string(),
            generation: 1,
            project_root: PathBuf::from("/retained-project"),
            node_id: "node-a".to_owned(),
            zone_id: "prod".to_owned(),
            // The longest supported UUID spelling must fit too, without
            // dropping historical identities to accommodate a smaller cap.
            session_nonces: (0..population)
                .map(|index| uuid::Uuid::from_u128(index as u128).urn().to_string())
                .collect(),
            actions: actions(1),
            fence_held: true,
            maintenance_hold_ids: Vec::new(),
            actions_applied: false,
            census_signature_hex: None,
        };
        let bytes = bounded_json(&drain, MAX_DRAIN_BYTES).unwrap();
        assert!(
            bytes.len() > 128 * 1024,
            "exercise the old accidental lower cap"
        );
        let decoded: StoredNativeSessionDrain = serde_json::from_str(&bytes).unwrap();
        assert_eq!(decoded.session_nonces, drain.session_nonces);
        let report = drain_report(&decoded, &[], &NativeSessionRecordAuthority::default()).unwrap();
        assert_eq!(report.checkpoint.admitted_sessions, population as u64);
        assert_eq!(report.checkpoint.indeterminate_sessions, population as u64);
        assert!(report.checkpoint.fence_held);
    }

    fn action_history(count: u64) -> Vec<FleetActionRecord> {
        (0..count)
            .map(|index| FleetActionRecord {
                action_id: format!("action-{index}"),
                emitted_at: DateTime::from_timestamp(
                    1_700_000_000 + i64::try_from(index).unwrap(),
                    0,
                )
                .unwrap(),
                action: crate::control_plane::fleet_transport::FleetAction::Release {
                    zone_id: "prod".to_owned(),
                    incident_id: format!("incident-{index}"),
                    reason: None,
                },
            })
            .collect()
    }

    fn begin_drain_at(
        root: &Path,
        project: &Path,
        node: &str,
        zone: &str,
        checkpoint: &FleetApplicationCheckpoint,
    ) -> Result<NativeSessionDrainReport> {
        super::begin_drain_at(
            root,
            project,
            node,
            zone,
            checkpoint,
            &action_history(checkpoint.action_count),
        )
    }

    fn maintenance_action(id: &str, resume: Option<&str>) -> FleetActionRecord {
        use crate::control_plane::fleet_transport::FleetAction;
        FleetActionRecord {
            action_id: id.to_owned(),
            emitted_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            action: match resume {
                None => FleetAction::NativeSessionHold {
                    zone_id: "prod".to_owned(),
                    reason: "operator maintenance".to_owned(),
                },
                Some(owner) => FleetAction::NativeSessionResume {
                    zone_id: "prod".to_owned(),
                    hold_action_id: owner.to_owned(),
                    reason: None,
                },
            },
        }
    }

    #[test]
    fn reference_admission_checks_ancestor_holds_until_every_owner_resumes() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 91);
        let project = admission.project_root.clone();
        let nested = project.join("nested/tests");
        let unrelated = temp.path().join("unrelated");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::create_dir_all(&unrelated).unwrap();
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        guard.worker_started();
        guard.worker_reaped();
        guard.finish(
            NativeSessionOutcomeKind::ControlStopped,
            successful_ledger_observation(),
        );
        enforce_reference_admission_at(&root, &nested).unwrap();
        let mut history = vec![
            maintenance_action("reference-hold-a", None),
            maintenance_action("reference-hold-b", None),
        ];
        let checkpoint = fleet_application_checkpoint(&history, "prod").unwrap();
        super::begin_drain_at(&root, &project, "node-a", "prod", &checkpoint, &history)
            .unwrap();
        let held = finish_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap();
        assert!(held.checkpoint.fence_held);
        assert_eq!(held.maintenance_hold_ids.len(), 2);
        // A nested input has no exact native-session row of its own. The
        // reference guard must still retain the ancestor's operator fence.
        assert_eq!(admission_ticket_at(&root, &nested).unwrap(), 0);
        assert!(enforce_reference_admission_at(&root, &project).is_err());
        assert!(enforce_reference_admission_at(&root, &nested).is_err());
        enforce_reference_admission_at(&root, &unrelated).unwrap();

        history.push(maintenance_action(
            "reference-resume-a",
            Some("reference-hold-a"),
        ));
        let checkpoint = fleet_application_checkpoint(&history, "prod").unwrap();
        super::begin_drain_at(&root, &project, "node-a", "prod", &checkpoint, &history)
            .unwrap();
        let one_owner = finish_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap();
        assert_eq!(one_owner.maintenance_hold_ids, vec!["reference-hold-b"]);
        assert!(enforce_reference_admission_at(&root, &nested).is_err());

        history.push(maintenance_action(
            "reference-resume-b",
            Some("reference-hold-b"),
        ));
        let checkpoint = fleet_application_checkpoint(&history, "prod").unwrap();
        super::begin_drain_at(&root, &project, "node-a", "prod", &checkpoint, &history)
            .unwrap();
        assert!(
            enforce_reference_admission_at(&root, &nested).is_err(),
            "publishing a resume cannot skip successful action application"
        );
        let resumed = finish_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap();
        assert!(resumed.checkpoint.is_complete());
        enforce_reference_admission_at(&root, &project).unwrap();
        enforce_reference_admission_at(&root, &nested).unwrap();
        assert!(!resumed.fleet_quiescence_certified);
    }

    #[test]
    fn reference_admission_refuses_malformed_ancestor_drain() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 92);
        let project = admission.project_root.clone();
        let _guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        let history = vec![maintenance_action("malformed-reference-hold", None)];
        let checkpoint = fleet_application_checkpoint(&history, "prod").unwrap();
        let drain = super::begin_drain_at(
            &root, &project, "node-a", "prod", &checkpoint, &history,
        )
        .unwrap();
        let connection = open_inventory(&root, false).unwrap().unwrap();
        let mut tx = connection.transaction().unwrap();
        tx.execute_with_params(
            "UPDATE native_session_drains SET state_json = ?1 WHERE drain_id = ?2;",
            &[
                SqliteValue::Text("{}".into()),
                SqliteValue::Text(drain.drain_id.into()),
            ],
        )
        .unwrap();
        tx.commit().unwrap();
        let error = enforce_reference_admission_at(&root, &project.join("nested"))
            .unwrap_err();
        assert!(format!("{error:#}").contains("decode native-session inventory record"));
    }

    #[test]
    fn reference_admission_does_not_initialize_an_absent_inventory() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("absent-evidence");
        enforce_reference_admission_at(&root, &temp.path().join("project")).unwrap();
        assert!(!root.exists());
        assert!(enforce_reference_admission_at(&root, Path::new("relative/project")).is_err());
    }

    #[test]
    fn maintenance_owners_hold_terminal_sessions_until_each_explicit_resume() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 61);
        let project = admission.project_root.clone();
        let nonce = admission.session_nonce.clone();
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        guard.worker_started();
        let mut history = vec![maintenance_action("hold-a", None)];
        let first_checkpoint = fleet_application_checkpoint(&history, "prod").unwrap();
        let pending = super::begin_drain_at(
            &root,
            &project,
            "node-a",
            "prod",
            &first_checkpoint,
            &history,
        )
        .unwrap();
        assert_eq!(pending.maintenance_hold_ids, vec!["hold-a"]);
        assert_eq!(pending.checkpoint.pending_sessions, 1);
        assert!(admission_ticket_at(&root, &project).is_err());
        guard.worker_reaped();
        guard.finish(
            NativeSessionOutcomeKind::ControlStopped,
            successful_ledger_observation(),
        );
        let held = finish_drain_at(&root, &project, "node-a", "prod", &first_checkpoint).unwrap();
        assert!(held.checkpoint.population_is_terminal());
        assert!(held.checkpoint.fence_held);
        assert!(!held.checkpoint.is_complete());
        assert_eq!(held.session_nonces, vec![nonce.clone()]);
        assert_eq!(held.maintenance_hold_ids, vec!["hold-a"]);
        assert!(admission_ticket_at(&root, &project).is_err());
        assert_eq!(
            super::begin_drain_at(
                &root,
                &project,
                "node-a",
                "prod",
                &first_checkpoint,
                &history,
            )
            .unwrap(),
            held,
            "reopening never drops a durable maintenance owner"
        );

        history.push(maintenance_action("hold-b", None));
        let second_checkpoint = fleet_application_checkpoint(&history, "prod").unwrap();
        let second = super::begin_drain_at(
            &root,
            &project,
            "node-a",
            "prod",
            &second_checkpoint,
            &history,
        )
        .unwrap();
        assert_eq!(second.generation, held.generation + 1);
        assert_eq!(second.session_nonces, held.session_nonces);
        assert_eq!(
            second.checkpoint.session_set_sha256,
            held.checkpoint.session_set_sha256
        );
        assert_eq!(second.maintenance_hold_ids, vec!["hold-a", "hold-b"]);
        assert!(second.checkpoint.fence_held);
        assert!(
            finish_drain_at(&root, &project, "node-a", "prod", &second_checkpoint)
                .unwrap()
                .checkpoint
                .fence_held
        );

        history.push(maintenance_action("resume-a", Some("hold-a")));
        let checkpoint = fleet_application_checkpoint(&history, "prod").unwrap();
        let begun = super::begin_drain_at(&root, &project, "node-a", "prod", &checkpoint, &history)
            .unwrap();
        assert_eq!(begun.maintenance_hold_ids, vec!["hold-b"]);
        let one_owner = finish_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap();
        assert!(one_owner.checkpoint.fence_held);
        assert!(admission_ticket_at(&root, &project).is_err());

        history.push(maintenance_action("resume-b", Some("hold-b")));
        let checkpoint = fleet_application_checkpoint(&history, "prod").unwrap();
        let applying =
            super::begin_drain_at(&root, &project, "node-a", "prod", &checkpoint, &history)
                .unwrap();
        assert!(applying.maintenance_hold_ids.is_empty());
        assert!(
            applying.checkpoint.fence_held,
            "resume still requires successful application"
        );
        assert!(admission_ticket_at(&root, &project).is_err());
        let resumed = finish_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap();
        assert!(resumed.checkpoint.is_complete());
        assert_eq!(resumed.session_nonces, vec![nonce]);
        assert_eq!(
            admission_ticket_at(&root, &project).unwrap(),
            resumed.generation
        );
        assert!(!resumed.fleet_quiescence_certified);
        assert!(
            super::begin_drain_at(
                &root,
                &project,
                "node-a",
                "prod",
                &first_checkpoint,
                &history[..1],
            )
            .is_err(),
            "old history cannot re-open or replace the applied snapshot"
        );
        let next =
            NativeSessionInventoryGuard::admit(&root, fixture(&root, 62), resumed.generation)
                .expect("explicit new admission after the final owner resumes");
        drop(next);
    }

    #[test]
    fn maximum_length_maintenance_owner_survives_reopen_and_explicit_resume() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 65);
        let project = admission.project_root.clone();
        drop(NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap());
        let owner = "h".repeat(128);
        let mut history = vec![maintenance_action(&owner, None)];
        let held_checkpoint = fleet_application_checkpoint(&history, "prod").unwrap();
        super::begin_drain_at(
            &root,
            &project,
            "node-a",
            "prod",
            &held_checkpoint,
            &history,
        )
        .unwrap();
        let held = finish_drain_at(&root, &project, "node-a", "prod", &held_checkpoint).unwrap();
        assert_eq!(held.maintenance_hold_ids, vec![owner.clone()]);
        assert!(held.checkpoint.fence_held);
        assert_eq!(
            super::begin_drain_at(
                &root,
                &project,
                "node-a",
                "prod",
                &held_checkpoint,
                &history
            )
            .unwrap(),
            held,
        );
        assert!(admission_ticket_at(&root, &project).is_err());
        history.push(maintenance_action("resume-long-owner", Some(&owner)));
        let resumed_checkpoint = fleet_application_checkpoint(&history, "prod").unwrap();
        super::begin_drain_at(
            &root,
            &project,
            "node-a",
            "prod",
            &resumed_checkpoint,
            &history,
        )
        .unwrap();
        let resumed =
            finish_drain_at(&root, &project, "node-a", "prod", &resumed_checkpoint).unwrap();
        assert!(resumed.maintenance_hold_ids.is_empty());
        assert!(resumed.checkpoint.is_complete());
        assert_eq!(
            admission_ticket_at(&root, &project).unwrap(),
            resumed.generation
        );
    }

    #[test]
    fn maintenance_resume_cannot_erase_pending_or_unknown_retained_effects() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 63);
        let project = admission.project_root.clone();
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        guard.worker_started();
        let mut history = vec![maintenance_action("hold-pending", None)];
        let retained = fleet_application_checkpoint(&history, "prod").unwrap();
        let pending =
            super::begin_drain_at(&root, &project, "node-a", "prod", &retained, &history).unwrap();
        history.push(maintenance_action("resume-pending", Some("hold-pending")));
        let latest = fleet_application_checkpoint(&history, "prod").unwrap();
        assert_eq!(
            super::begin_drain_at(&root, &project, "node-a", "prod", &latest, &history,).unwrap(),
            pending
        );
        assert!(finish_drain_at(&root, &project, "node-a", "prod", &latest).is_err());
        guard.worker_reaped();
        guard.finish(
            NativeSessionOutcomeKind::ControlStopped,
            NativeSessionEffectObservation::Unknown,
        );
        let unknown = finish_drain_at(&root, &project, "node-a", "prod", &retained).unwrap();
        assert_eq!(unknown.checkpoint.indeterminate_sessions, 1);
        assert_eq!(unknown.maintenance_hold_ids, vec!["hold-pending"]);
        assert!(unknown.checkpoint.fence_held);
        assert_eq!(
            super::begin_drain_at(&root, &project, "node-a", "prod", &latest, &history,).unwrap(),
            unknown
        );
        assert!(admission_ticket_at(&root, &project).is_err());
        assert!(
            super::begin_drain_at(&root, &project, "another-node", "prod", &latest, &history,)
                .is_err()
        );
    }

    #[test]
    fn terminal_population_cannot_advance_an_unapplied_hold_or_ordinary_drain() {
        for maintenance in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let admission = fixture(&root, 64);
            let project = admission.project_root.clone();
            // A session that never spawned is positively terminal, but that
            // says nothing about whether its fleet actions were applied.
            drop(NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap());
            let first_history = if maintenance {
                vec![maintenance_action("hold-unapplied", None)]
            } else {
                action_history(1)
            };
            let first_checkpoint = fleet_application_checkpoint(&first_history, "prod").unwrap();
            let first = super::begin_drain_at(
                &root,
                &project,
                "node-a",
                "prod",
                &first_checkpoint,
                &first_history,
            )
            .unwrap();
            assert!(first.checkpoint.population_is_terminal());
            assert!(first.checkpoint.fence_held);
            let latest_history = if maintenance {
                let mut history = first_history.clone();
                history.push(maintenance_action(
                    "resume-unapplied",
                    Some("hold-unapplied"),
                ));
                history
            } else {
                action_history(2)
            };
            let latest_checkpoint = fleet_application_checkpoint(&latest_history, "prod").unwrap();
            assert_eq!(
                super::begin_drain_at(
                    &root,
                    &project,
                    "node-a",
                    "prod",
                    &latest_checkpoint,
                    &latest_history,
                )
                .unwrap(),
                first
            );
            assert!(admission_ticket_at(&root, &project).is_err());
            let applied =
                finish_drain_at(&root, &project, "node-a", "prod", &first_checkpoint).unwrap();
            assert_eq!(applied.checkpoint.fence_held, maintenance);
            let advancing = super::begin_drain_at(
                &root,
                &project,
                "node-a",
                "prod",
                &latest_checkpoint,
                &latest_history,
            )
            .unwrap();
            assert_eq!(advancing.checkpoint.applied_actions, latest_checkpoint);
            assert!(advancing.checkpoint.fence_held);
            assert_eq!(advancing.session_nonces, first.session_nonces);
            assert!(
                finish_drain_at(&root, &project, "node-a", "prod", &latest_checkpoint,)
                    .unwrap()
                    .checkpoint
                    .is_complete()
            );
        }
    }

    fn successful_ledger_observation() -> NativeSessionEffectObservation {
        NativeSessionEffectObservation::FinalLedgerObserved {
            effect_count: 3,
            allowed_count: 2,
            denied_count: 1,
            failed_count: 0,
            chain_head_hash: format!("sha256:{}", "a".repeat(64)),
            ledger_sha256: "b".repeat(64),
        }
    }

    fn terminal_outcome() -> NativeSessionOutcome {
        NativeSessionOutcome {
            observed_at: Utc::now(),
            kind: NativeSessionOutcomeKind::ControlStopped,
            process: NativeSessionProcessObservation::WorkerReaped,
            containment_empty_observed: false,
            effects: successful_ledger_observation(),
        }
    }

    fn abandon_after_receipt(
        root: &Path,
        mut guard: NativeSessionInventoryGuard,
        outcome: &NativeSessionOutcome,
    ) {
        // Exercise the real durable publication boundary without committing
        // its database projection. This models that exact crash window, not
        // process cleanup or host-ledger signature verification.
        retain_outcome_receipt(root, &guard.admission, outcome).unwrap();
        guard.finished = true;
        drop(guard);
    }

    #[test]
    fn retained_outcome_recovers_terminal_drain_after_database_commit_was_lost() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 50);
        let project = admission.project_root.clone();
        let path = outcome_receipt_path(&root, &admission.session_nonce);
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        guard.worker_started();
        let started = begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert_eq!(started.checkpoint.pending_sessions, 1);
        guard.worker_reaped();
        let outcome = terminal_outcome();
        abandon_after_receipt(&root, guard, &outcome);
        let retained_bytes = std::fs::read(&path).unwrap();

        // A status read must neither repair the database nor release a fence.
        let before = read_inventory_at(&root, None).unwrap();
        assert_eq!(before.pending_sessions, 1);
        assert!(before.records[0].outcome.is_none());
        assert!(admission_ticket_at(&root, &project).is_err());

        let recovered = finish_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert_eq!(recovered.drain_id, started.drain_id);
        assert_eq!(recovered.session_nonces, started.session_nonces);
        assert_eq!(recovered.checkpoint.terminal_sessions, 1);
        assert!(recovered.checkpoint.is_complete());
        assert!(!recovered.fleet_quiescence_certified);
        let inventory = read_inventory_at(&root, None).unwrap();
        assert_eq!(inventory.pending_sessions, 0);
        assert_eq!(inventory.records[0].outcome.as_ref(), Some(&outcome));
        assert_eq!(std::fs::read(&path).unwrap(), retained_bytes);
        assert_eq!(
            finish_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap(),
            recovered
        );
        // A new launch can be admitted only under the recovered generation;
        // recovery does not automatically restart the old application.
        let next = fixture(&root, 51);
        let resumed =
            NativeSessionInventoryGuard::admit(&root, next, recovered.generation).unwrap();
        drop(resumed);
    }

    #[test]
    fn retained_unspawned_outcome_recovers_without_claiming_a_worker_reap() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 52);
        let project = admission.project_root.clone();
        let guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        let outcome = NativeSessionOutcome {
            observed_at: Utc::now(),
            kind: NativeSessionOutcomeKind::SupervisionIncomplete,
            process: NativeSessionProcessObservation::NotSpawned,
            containment_empty_observed: false,
            effects: NativeSessionEffectObservation::NotStarted,
        };
        abandon_after_receipt(&root, guard, &outcome);
        let started = begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert_eq!(started.checkpoint.terminal_sessions, 1);
        assert!(
            started.checkpoint.fence_held,
            "policy application is still required"
        );
        let completed = finish_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert!(completed.checkpoint.is_complete());
        let inventory = read_inventory_at(&root, None).unwrap();
        assert_eq!(inventory.terminal_sessions, 0, "no worker was reaped");
        assert_eq!(inventory.records[0].outcome.as_ref(), Some(&outcome));
    }

    #[test]
    fn recovered_unknown_failed_or_uncontained_observations_keep_the_fence_held() {
        for case in 0..5 {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let mut admission = fixture(&root, 53);
            let project = admission.project_root.clone();
            let mut outcome = terminal_outcome();
            match case {
                0 => outcome.effects = final_ledger_observation(),
                1 => {
                    outcome.kind = NativeSessionOutcomeKind::SupervisionIncomplete;
                    outcome.process = NativeSessionProcessObservation::Unproven;
                    outcome.effects = NativeSessionEffectObservation::Unknown;
                }
                2 => {
                    outcome.kind = NativeSessionOutcomeKind::TelemetryFailed;
                    outcome.effects = NativeSessionEffectObservation::Unknown;
                }
                3 => admission.process_spawn_authority_granted = Some(true),
                4 => admission.process_spawn_authority_granted = None,
                _ => unreachable!(),
            }
            let guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
            abandon_after_receipt(&root, guard, &outcome);
            let started = begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
            assert_eq!(started.checkpoint.pending_sessions, 0, "case {case}");
            assert_eq!(started.checkpoint.indeterminate_sessions, 1, "case {case}");
            let held = finish_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
            assert_eq!(held, started);
            assert!(admission_ticket_at(&root, &project).is_err());
            assert_eq!(
                read_inventory_at(&root, None).unwrap().records[0]
                    .outcome
                    .as_ref(),
                Some(&outcome)
            );
        }
    }

    #[test]
    fn outcome_receipt_tampering_and_foreign_signatures_cannot_recover_a_session() {
        for case in 0..8 {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let admission = fixture(&root, 54);
            let project = admission.project_root.clone();
            let path = outcome_receipt_path(&root, &admission.session_nonce);
            let guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
            abandon_after_receipt(&root, guard, &terminal_outcome());
            let mut receipt: NativeSessionOutcomeReceipt =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            match case {
                0 => receipt.outcome.kind = NativeSessionOutcomeKind::Completed,
                1 => receipt.session_nonce = uuid::Uuid::now_v7().to_string(),
                2 => receipt.product_root_key_id = format!("ed25519:{}", "a".repeat(64)),
                3 => receipt.admission_sha256 = "a".repeat(64),
                4 => receipt.schema_version.push_str("-unsupported"),
                5 => receipt.signature_hex.clear(),
                6 => {
                    use ed25519_dalek::Signer as _;
                    let foreign = ed25519_dalek::SigningKey::from_bytes(&[99; 32]);
                    receipt.signature_hex =
                        hex::encode(foreign.sign(&receipt.preimage().unwrap()).to_bytes());
                }
                7 => receipt.outcome.containment_empty_observed = true,
                _ => unreachable!(),
            }
            std::fs::write(&path, serde_json::to_vec(&receipt).unwrap()).unwrap();
            assert!(
                begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).is_err(),
                "case {case}"
            );
            let unchanged = read_inventory_at(&root, None).unwrap();
            assert_eq!(unchanged.pending_sessions, 1, "case {case}");
            assert!(unchanged.records[0].outcome.is_none());
        }
    }

    #[test]
    fn changed_admission_cannot_reuse_an_authenticated_outcome() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let mut admission = fixture(&root, 55);
        let project = admission.project_root.clone();
        let guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        abandon_after_receipt(&root, guard, &terminal_outcome());
        admission.dependency_ids.push("new-dependency".to_owned());
        admission.process_spawn_authority_granted = Some(true);
        let connection = open_inventory(&root, false).unwrap().unwrap();
        let mut tx = connection.transaction().unwrap();
        tx.execute_with_params(
            "UPDATE native_sessions SET admission_json = ?1 WHERE session_nonce = ?2;",
            &[
                SqliteValue::Text(serde_json::to_string(&admission).unwrap().into()),
                SqliteValue::Text(admission.session_nonce.into()),
            ],
        )
        .unwrap();
        tx.commit().unwrap();
        assert!(begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).is_err());
        assert_eq!(read_inventory_at(&root, None).unwrap().pending_sessions, 1);
    }

    #[test]
    fn invalid_receipt_aborts_the_whole_recovery_batch_without_partial_changes() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let first = fixture(&root, 56);
        let second = fixture(&root, 57);
        let project = first.project_root.clone();
        let first_path = outcome_receipt_path(&root, &first.session_nonce);
        let second_path = outcome_receipt_path(&root, &second.session_nonce);
        let first_guard = NativeSessionInventoryGuard::admit(&root, first, 0).unwrap();
        let second_guard = NativeSessionInventoryGuard::admit(&root, second, 0).unwrap();
        abandon_after_receipt(&root, first_guard, &terminal_outcome());
        abandon_after_receipt(&root, second_guard, &terminal_outcome());
        // A genuine signature from the same product root still cannot be
        // replayed as the terminal observation of a different launch.
        std::fs::write(&second_path, std::fs::read(first_path).unwrap()).unwrap();
        assert!(begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).is_err());
        let unchanged = read_inventory_at(&root, None).unwrap();
        assert_eq!(unchanged.pending_sessions, 2);
        assert!(
            unchanged
                .records
                .iter()
                .all(|record| record.outcome.is_none())
        );
    }

    #[test]
    fn recovery_cannot_replace_a_concurrently_persisted_different_observation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 58);
        let guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        abandon_after_receipt(&root, guard, &terminal_outcome());
        let connection = open_inventory(&root, false).unwrap().unwrap();
        let pending = read_records(&connection).unwrap();
        let observed = NativeSessionOutcome {
            observed_at: Utc::now(),
            kind: NativeSessionOutcomeKind::SupervisionIncomplete,
            process: NativeSessionProcessObservation::WorkerReaped,
            containment_empty_observed: false,
            effects: NativeSessionEffectObservation::Unknown,
        };
        let mut tx = connection.transaction().unwrap();
        tx.execute_with_params(
            "UPDATE native_sessions SET outcome_json = ?1 WHERE session_nonce = ?2;",
            &[
                SqliteValue::Text(serde_json::to_string(&observed).unwrap().into()),
                SqliteValue::Text(admission.session_nonce.into()),
            ],
        )
        .unwrap();
        tx.commit().unwrap();
        assert!(recover_retained_outcomes(&root, &connection, &pending).is_err());
        assert_eq!(
            read_records(&connection).unwrap()[0].outcome.as_ref(),
            Some(&observed)
        );
    }

    #[test]
    fn oversized_outcome_receipt_is_refused_before_recovery() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 59);
        let project = admission.project_root.clone();
        let path = outcome_receipt_path(&root, &admission.session_nonce);
        let guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        abandon_after_receipt(&root, guard, &terminal_outcome());
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_len(u64::try_from(MAX_OUTCOME_RECEIPT_BYTES + 1).unwrap())
            .unwrap();
        assert!(begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).is_err());
        assert_eq!(read_inventory_at(&root, None).unwrap().pending_sessions, 1);
    }

    #[test]
    fn supervisor_attestation_binds_fresh_held_population_without_private_inputs() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 81);
        let project = admission.project_root.clone();
        let nonce = admission.session_nonce.clone();
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        guard.worker_started();
        guard.worker_reaped();
        guard.finish(
            NativeSessionOutcomeKind::ControlStopped,
            successful_ledger_observation(),
        );
        let history = vec![maintenance_action("hold-authenticated", None)];
        let checkpoint = fleet_application_checkpoint(&history, "prod").unwrap();
        super::begin_drain_at(&root, &project, "node-a", "prod", &checkpoint, &history).unwrap();
        let unapplied =
            attest_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap_err();
        assert!(unapplied.to_string().contains("confirmed application"));
        let held = finish_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap();
        let signed = attest_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap();
        assert_eq!(signed.drain_id, held.drain_id);
        assert_eq!(signed.generation, held.generation);
        assert_eq!(signed.session_nonces, held.session_nonces);
        assert_eq!(signed.checkpoint.admitted_sessions, 1);
        assert_eq!(signed.checkpoint.terminal_sessions, 1);
        assert!(signed.checkpoint.fence_held);
        assert!(!signed.fleet_quiescence_certified);
        let attestation = signed.checkpoint.supervisor_attestation.as_ref().unwrap();
        let trusted_root = ed25519_dalek::SigningKey::from_bytes(&[17; 32]).verifying_key();
        attestation
            .verify(&signed.checkpoint, "node-a", "prod", &trusted_root)
            .unwrap();
        attestation.validate_freshness(Utc::now()).unwrap();
        let public_json = serde_json::to_string(&signed.checkpoint).unwrap();
        for private in [project.to_str().unwrap(), nonce.as_str(), "package-a"] {
            assert!(
                !public_json.contains(private),
                "private field leaked: {private}"
            );
        }
        let mut altered = signed.checkpoint.clone();
        altered.session_set_sha256 = "c".repeat(64);
        assert!(
            attestation
                .verify(&altered, "node-a", "prod", &trusted_root)
                .is_err()
        );
        assert!(
            attestation
                .verify(&signed.checkpoint, "node-b", "prod", &trusted_root)
                .is_err()
        );
        let foreign_root = ed25519_dalek::SigningKey::from_bytes(&[99; 32]).verifying_key();
        assert!(
            attestation
                .verify(&signed.checkpoint, "node-a", "prod", &foreign_root)
                .is_err()
        );
        assert!(attest_drain_at(&root, &project, "node-b", "prod", &checkpoint).is_err());
        assert!(attest_drain_at(&root, &project, "node-a", "prod", &actions(2)).is_err());
    }

    #[test]
    fn unsigned_database_terminal_outcome_remains_indeterminate_when_attested() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 82);
        let project = admission.project_root.clone();
        let nonce = admission.session_nonce.clone();
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        guard.worker_started();
        // Model a forged terminal database projection without any supervisor
        // receipt. A matching shape and real admission are insufficient.
        guard.finished = true;
        drop(guard);
        let forged = terminal_outcome();
        let connection = open_inventory(&root, false).unwrap().unwrap();
        let mut tx = connection.transaction().unwrap();
        tx.execute_with_params(
            "UPDATE native_sessions SET outcome_json = ?1 WHERE session_nonce = ?2;",
            &[
                SqliteValue::Text(serde_json::to_string(&forged).unwrap().into()),
                SqliteValue::Text(nonce.into()),
            ],
        )
        .unwrap();
        tx.commit().unwrap();
        let started = begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert_eq!(started.checkpoint.terminal_sessions, 0);
        assert_eq!(started.checkpoint.indeterminate_sessions, 1);
        let held = finish_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert!(held.checkpoint.fence_held);
        let signed = attest_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert_eq!(signed.checkpoint.terminal_sessions, 0);
        assert_eq!(signed.checkpoint.indeterminate_sessions, 1);
        assert!(signed.checkpoint.supervisor_attestation.is_some());
        assert!(!signed.checkpoint.is_complete());
        assert!(admission_ticket_at(&root, &project).is_err());
        assert_eq!(
            read_records(&connection).unwrap()[0].outcome.as_ref(),
            Some(&forged)
        );
    }

    #[test]
    fn altered_signed_outcome_cannot_be_promoted_into_a_drain_attestation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 83);
        let project = admission.project_root.clone();
        let path = outcome_receipt_path(&root, &admission.session_nonce);
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        guard.worker_started();
        guard.worker_reaped();
        guard.finish(
            NativeSessionOutcomeKind::ControlStopped,
            successful_ledger_observation(),
        );
        let history = vec![maintenance_action("held", None)];
        let checkpoint = fleet_application_checkpoint(&history, "prod").unwrap();
        super::begin_drain_at(&root, &project, "node-a", "prod", &checkpoint, &history).unwrap();
        finish_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap();
        let mut receipt: NativeSessionOutcomeReceipt =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        receipt.outcome.containment_empty_observed = true;
        std::fs::write(&path, serde_json::to_vec(&receipt).unwrap()).unwrap();
        assert!(attest_drain_at(&root, &project, "node-a", "prod", &checkpoint).is_err());
        assert!(finish_drain_at(&root, &project, "node-a", "prod", &checkpoint).is_err());
        assert!(admission_ticket_at(&root, &project).is_err());
    }

    #[test]
    fn signed_pending_admission_cannot_be_moved_out_of_its_project_census() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let mut admission = fixture(&root, 84);
        let project = admission.project_root.clone();
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        guard.worker_started();
        guard.finished = true;
        drop(guard);
        begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        finish_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        admission.project_root = temp.path().join("different-project");
        admission.entrypoint = admission.project_root.join("index.js");
        let connection = open_inventory(&root, false).unwrap().unwrap();
        let mut tx = connection.transaction().unwrap();
        tx.execute_with_params(
            "UPDATE native_sessions SET admission_json = ?1 WHERE session_nonce = ?2;",
            &[
                SqliteValue::Text(serde_json::to_string(&admission).unwrap().into()),
                SqliteValue::Text(admission.session_nonce.into()),
            ],
        )
        .unwrap();
        tx.commit().unwrap();
        assert!(attest_drain_at(&root, &project, "node-a", "prod", &actions(1)).is_err());
        assert!(finish_drain_at(&root, &project, "node-a", "prod", &actions(1)).is_err());
        assert!(admission_ticket_at(&root, &project).is_err());
    }

    #[test]
    fn historical_unbound_pending_admission_remains_in_every_project_census() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 85);
        let nonce = admission.session_nonce.clone();
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        guard.worker_started();
        guard.finished = true;
        drop(guard);
        // Preserve the receipt separately to model an older admitted record
        // that predates full admission signatures. Never re-sign its DB facts.
        let path = admission_receipt_path(&root, &nonce);
        std::fs::rename(&path, path.with_extension("preserved")).unwrap();
        let another_project = temp.path().join("another-project");
        let started =
            begin_drain_at(&root, &another_project, "node-a", "prod", &actions(1)).unwrap();
        assert_eq!(started.session_nonces, vec![nonce]);
        assert_eq!(started.checkpoint.indeterminate_sessions, 1);
        assert_eq!(started.checkpoint.terminal_sessions, 0);
        finish_drain_at(&root, &another_project, "node-a", "prod", &actions(1)).unwrap();
        let signed =
            attest_drain_at(&root, &another_project, "node-a", "prod", &actions(1)).unwrap();
        assert!(signed.checkpoint.fence_held);
        assert_eq!(signed.checkpoint.indeterminate_sessions, 1);
        assert!(!signed.fleet_quiescence_certified);
    }

    #[test]
    fn fence_refusal_retains_authenticated_unspawned_outcome_without_poisoning_held_census() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let initial = fixture(&root, 86);
        let project = initial.project_root.clone();
        drop(NativeSessionInventoryGuard::admit(&root, initial, 0).unwrap());
        let history = vec![maintenance_action("held", None)];
        let checkpoint = fleet_application_checkpoint(&history, "prod").unwrap();
        super::begin_drain_at(&root, &project, "node-a", "prod", &checkpoint, &history).unwrap();
        let held = finish_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap();
        let denied = fixture(&root, 87);
        // A newly captured identity is unknown until the refused admission
        // retains an authenticated never-spawned outcome.
        let unknown = attest_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap_err();
        assert!(unknown.to_string().contains("population changed"));
        assert!(
            NativeSessionInventoryGuard::admit(&root, denied.clone(), held.generation).is_err()
        );
        let key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]).verifying_key();
        assert!(
            read_admission_receipt(&root, &denied, &key)
                .unwrap()
                .is_some()
        );
        let receipt = read_outcome_receipt(&root, &denied, &key).unwrap().unwrap();
        assert_eq!(
            receipt.outcome.process,
            NativeSessionProcessObservation::NotSpawned
        );
        assert_eq!(
            receipt.outcome.effects,
            NativeSessionEffectObservation::NotStarted
        );
        let signed = attest_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap();
        assert_eq!(signed.session_nonces, held.session_nonces);
        assert_eq!(signed.checkpoint.terminal_sessions, 1);
        assert!(signed.checkpoint.fence_held);
        assert!(signed.checkpoint.supervisor_attestation.is_some());
        assert_eq!(read_inventory_at(&root, None).unwrap().records.len(), 2);
    }

    #[test]
    fn rejected_duplicate_admission_cannot_sign_a_running_session_as_never_spawned() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 90);
        let project = admission.project_root.clone();
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        guard.worker_started();
        begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert!(NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).is_err());
        let root_key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]).verifying_key();
        assert!(
            read_outcome_receipt(&root, &admission, &root_key)
                .unwrap()
                .is_none()
        );
        let pending = finish_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert!(pending.checkpoint.fence_held);
        assert_eq!(pending.checkpoint.pending_sessions, 1);
        assert_eq!(pending.checkpoint.terminal_sessions, 0);
        guard.worker_reaped();
        guard.finish(
            NativeSessionOutcomeKind::ControlStopped,
            successful_ledger_observation(),
        );
        assert!(
            finish_drain_at(&root, &project, "node-a", "prod", &actions(1))
                .unwrap()
                .checkpoint
                .is_complete()
        );
    }

    #[test]
    fn released_cohort_attestation_preserves_later_current_policy_sessions() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let initial = fixture(&root, 88);
        let project = initial.project_root.clone();
        drop(NativeSessionInventoryGuard::admit(&root, initial, 0).unwrap());
        begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        let completed = finish_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        let before = attest_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert!(before.checkpoint.is_complete());
        let next = fixture(&root, 89);
        let mut guard =
            NativeSessionInventoryGuard::admit(&root, next, completed.generation).unwrap();
        guard.worker_started();
        let during = attest_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert_eq!(during.drain_id, before.drain_id);
        assert_eq!(during.generation, before.generation);
        assert_eq!(during.session_nonces, before.session_nonces);
        assert_eq!(during.checkpoint.admitted_sessions, 1);
        assert!(!during.checkpoint.fence_held);
        assert!(!during.fleet_quiescence_certified);
        assert_eq!(read_inventory_at(&root, None).unwrap().pending_sessions, 1);
        let same = begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert_eq!(same.generation, before.generation);
        assert!(!same.checkpoint.fence_held);
        assert_eq!(
            admission_ticket_at(&root, &project).unwrap(),
            before.generation
        );
        guard.worker_reaped();
        guard.finish(
            NativeSessionOutcomeKind::ControlStopped,
            successful_ledger_observation(),
        );
        let historical = attest_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert_eq!(historical.session_nonces, before.session_nonces);
        assert_eq!(historical.checkpoint.admitted_sessions, 1);
        let next = begin_drain_at(&root, &project, "node-a", "prod", &actions(2)).unwrap();
        assert_eq!(next.checkpoint.admitted_sessions, 2);
        finish_drain_at(&root, &project, "node-a", "prod", &actions(2)).unwrap();
        assert!(
            attest_drain_at(&root, &project, "node-a", "prod", &actions(2))
                .unwrap()
                .checkpoint
                .is_complete()
        );
    }

    #[test]
    fn released_census_cannot_be_replaced_before_its_first_public_attestation() {
        for mutation in 0..4 {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let admission = fixture(&root, 91);
            let project = admission.project_root.clone();
            drop(NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap());
            begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
            finish_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
            let connection = open_inventory(&root, false).unwrap().unwrap();
            let mut tx = connection.transaction().unwrap();
            let mut retained = latest_drain(&tx, &project).unwrap().unwrap();
            match mutation {
                0 => retained.session_nonces.clear(),
                1 => retained.session_nonces = vec![uuid::Uuid::now_v7().to_string()],
                2 => retained.census_signature_hex = None,
                _ => retained.census_signature_hex = Some("0".repeat(128)),
            }
            tx.execute_with_params(
                "UPDATE native_session_drains SET state_json = ?1 WHERE drain_id = ?2;",
                &[
                    SqliteValue::Text(serde_json::to_string(&retained).unwrap().into()),
                    SqliteValue::Text(retained.drain_id.into()),
                ],
            )
            .unwrap();
            tx.commit().unwrap();
            let error =
                attest_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap_err();
            assert!(
                format!("{error:#}").contains("census"),
                "mutation {mutation}: {error:#}"
            );
            if mutation == 2 {
                // Legacy rows stay inspectable but are never re-sealed from
                // mutable database values. Only a newly captured action
                // snapshot creates a fresh, authenticated initial census.
                begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
                finish_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
                assert!(attest_drain_at(&root, &project, "node-a", "prod", &actions(1)).is_err());
                begin_drain_at(&root, &project, "node-a", "prod", &actions(2)).unwrap();
                finish_drain_at(&root, &project, "node-a", "prod", &actions(2)).unwrap();
                let next = attest_drain_at(&root, &project, "node-a", "prod", &actions(2)).unwrap();
                assert_eq!(next.checkpoint.admitted_sessions, 1);
                assert!(next.checkpoint.supervisor_attestation.is_some());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn agent_ownership_spans_reconciliation_and_releases_without_removing_history() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 39);
        let project = admission.project_root;
        let first = acquire_agent_at(&root, &project).unwrap();
        assert!(acquire_agent_at(&root, &project).is_err());
        let independent = acquire_agent_at(&root, &temp.path().join("another-project")).unwrap();
        drop(independent);
        let before = std::fs::read_dir(&root).unwrap().count();
        drop(first);
        let _resumed = acquire_agent_at(&root, &project).unwrap();
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), before);
    }

    #[test]
    fn drain_fences_admission_and_reopens_only_after_verified_terminal_accounting() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 31);
        let project = admission.project_root.clone();
        let nonce = admission.session_nonce.clone();
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        guard.worker_started();
        let started = begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert_eq!(started.session_nonces, vec![nonce]);
        assert_eq!(started.checkpoint.pending_sessions, 1);
        assert!(started.checkpoint.fence_held);
        assert!(!started.fleet_quiescence_certified);
        assert!(admission_ticket_at(&root, &project).is_err());
        let still_pending =
            finish_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert_eq!(still_pending, started);

        guard.worker_reaped();
        guard.finish(
            NativeSessionOutcomeKind::ControlStopped,
            successful_ledger_observation(),
        );
        // A new connection sees the durable population and final observation.
        let completed = finish_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert!(completed.checkpoint.is_complete());
        assert_eq!(completed.checkpoint.terminal_sessions, 1);
        assert_eq!(
            completed.checkpoint.session_set_sha256,
            started.checkpoint.session_set_sha256
        );
        assert_eq!(
            admission_ticket_at(&root, &project).unwrap(),
            completed.generation
        );
        assert_eq!(
            begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap(),
            completed
        );
        assert!(!completed.fleet_quiescence_certified);

        // A preflight that began before the drain cannot sneak through after
        // completion. Its identity is retained as positively never spawned.
        let stale = fixture(&root, 32);
        let stale_nonce = stale.session_nonce.clone();
        assert!(NativeSessionInventoryGuard::admit(&root, stale, 0).is_err());
        let inventory = read_inventory_at(&root, None).unwrap();
        let refused = inventory
            .records
            .iter()
            .find(|record| record.admission.session_nonce == stale_nonce)
            .unwrap();
        assert_eq!(
            refused.outcome.as_ref().unwrap().process,
            NativeSessionProcessObservation::NotSpawned
        );
        assert!(inventory.untracked_identity_captures.is_empty());
        let fresh =
            NativeSessionInventoryGuard::admit(&root, fixture(&root, 33), completed.generation)
                .unwrap();
        drop(fresh);
        let next = begin_drain_at(&root, &project, "node-a", "prod", &actions(2)).unwrap();
        assert_eq!(next.generation, completed.generation + 1);
        assert_eq!(next.checkpoint.admitted_sessions, 3);
        assert_eq!(next.checkpoint.terminal_sessions, 3);
        assert!(
            next.checkpoint.fence_held,
            "terminal accounting alone must not bypass application"
        );
    }

    #[test]
    fn interrupted_or_failed_effects_hold_the_original_fence_across_newer_actions() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 34);
        let project = admission.project_root.clone();
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        guard.worker_started();
        let started = begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        guard.worker_reaped();
        let mut ledger = successful_ledger_observation();
        if let NativeSessionEffectObservation::FinalLedgerObserved {
            allowed_count,
            failed_count,
            ..
        } = &mut ledger
        {
            *failed_count = *allowed_count;
            *allowed_count = 0;
        }
        guard.finish(NativeSessionOutcomeKind::ControlStopped, ledger);
        let held = finish_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert_eq!(held.checkpoint.indeterminate_sessions, 1);
        assert!(held.checkpoint.fence_held);
        assert_eq!(held.drain_id, started.drain_id);
        assert_eq!(
            begin_drain_at(&root, &project, "node-a", "prod", &actions(2)).unwrap(),
            held
        );
        assert_eq!(
            begin_drain_at(&root, &project, "node-a", "prod", &actions(0)).unwrap(),
            held
        );
        assert!(finish_drain_at(&root, &project, "node-a", "prod", &actions(2)).is_err());
        assert!(finish_drain_at(&root, &project, "other-node", "prod", &actions(1)).is_err());
        assert!(begin_drain_at(&root, &project, "node-a", "other-zone", &actions(2)).is_err());
        assert!(admission_ticket_at(&root, &project).is_err());
    }

    #[test]
    fn historical_or_uncontained_process_authority_cannot_be_promoted_to_terminal() {
        for (authority, empty, expected_terminal) in [
            (None, false, false),
            (None, true, false),
            (Some(true), false, false),
            (Some(true), true, true),
            (Some(false), false, true),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let mut admission = fixture(&root, 35);
            admission.process_spawn_authority_granted = authority;
            let project = admission.project_root.clone();
            let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
            guard.worker_started();
            guard.worker_reaped();
            if empty {
                guard.containment_empty();
            }
            guard.finish(
                NativeSessionOutcomeKind::Completed,
                successful_ledger_observation(),
            );
            begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
            let result = finish_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
            assert_eq!(
                result.checkpoint.is_complete(),
                expected_terminal,
                "authority={authority:?} empty={empty}"
            );
            assert_eq!(
                result.checkpoint.indeterminate_sessions,
                u64::from(!expected_terminal)
            );
        }
    }

    #[test]
    fn cooperative_unused_process_authority_requires_containment_and_known_effects() {
        for (empty, failed, expected_terminal) in [
            (false, false, false),
            (true, false, true),
            (true, true, false),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let mut admission = fixture(&root, 35);
            admission.process_spawn_authority_granted = Some(true);
            let project = admission.project_root.clone();
            let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
            guard.worker_started();
            begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
            guard.worker_reaped();
            if empty {
                guard.containment_empty();
            }
            let effects = NativeSessionEffectObservation::FinalLedgerObserved {
                effect_count: usize::from(failed),
                allowed_count: 0,
                denied_count: 0,
                failed_count: usize::from(failed),
                chain_head_hash: format!("sha256:{}", "a".repeat(64)),
                ledger_sha256: "b".repeat(64),
            };
            guard.finish(NativeSessionOutcomeKind::ControlStopped, effects);
            let result = finish_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
            assert_eq!(result.checkpoint.is_complete(), expected_terminal);
            assert_eq!(
                result.checkpoint.terminal_sessions,
                u64::from(expected_terminal)
            );
            assert_eq!(
                result.checkpoint.indeterminate_sessions,
                u64::from(!expected_terminal)
            );
            assert_eq!(result.checkpoint.fence_held, !expected_terminal);
            assert!(!result.fleet_quiescence_certified);
            assert_eq!(
                admission_ticket_at(&root, &project).is_ok(),
                expected_terminal
            );
        }
    }

    #[test]
    fn untracked_identity_is_retained_even_when_its_project_is_unknown() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let old = fixture(&root, 36);
        let other_project = temp.path().join("different-project");
        let started = begin_drain_at(&root, &other_project, "node-a", "prod", &actions(1)).unwrap();
        assert_eq!(started.session_nonces, vec![old.session_nonce]);
        assert_eq!(started.checkpoint.indeterminate_sessions, 1);
        assert_eq!(
            finish_drain_at(&root, &other_project, "node-a", "prod", &actions(1)).unwrap(),
            started
        );
    }

    #[test]
    fn initial_empty_snapshot_is_idempotent_but_cannot_erase_later_history() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 37);
        let project = admission.project_root.clone();
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        let empty = begin_drain_at(&root, &project, "node-a", "prod", &actions(0)).unwrap();
        assert!(empty.checkpoint.is_complete());
        assert_eq!(empty.checkpoint.admitted_sessions, 0);
        assert_eq!(
            begin_drain_at(&root, &project, "node-a", "prod", &actions(0)).unwrap(),
            empty
        );
        guard.finish(
            NativeSessionOutcomeKind::SupervisionIncomplete,
            NativeSessionEffectObservation::NotStarted,
        );
        begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        let completed = finish_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert!(completed.checkpoint.is_complete());
        assert!(begin_drain_at(&root, &project, "node-a", "prod", &actions(0)).is_err());
        let mut contradictory = actions(1);
        contradictory.actions_sha256 = "f".repeat(64);
        assert!(begin_drain_at(&root, &project, "node-a", "prod", &contradictory).is_err());
        let mut rewritten = action_history(2);
        rewritten[0].action_id = "rewritten-predecessor".to_owned();
        let rewritten_checkpoint = fleet_application_checkpoint(&rewritten, "prod").unwrap();
        assert!(
            super::begin_drain_at(
                &root,
                &project,
                "node-a",
                "prod",
                &rewritten_checkpoint,
                &rewritten,
            )
            .is_err()
        );
        assert_eq!(
            begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap(),
            completed,
            "contradictory longer history must not replace the retained completed checkpoint"
        );
    }

    #[test]
    fn simultaneous_admission_and_fence_never_lose_a_worker_obligation() {
        for _ in 0..4 {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let admission = fixture(&root, 38);
            let project = admission.project_root.clone();
            let nonce = admission.session_nonce.clone();
            // Establish the schema before racing independent connections.
            open_inventory(&root, true).unwrap();
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let start = std::sync::Arc::clone(&barrier);
            let worker_root = root.clone();
            let worker = std::thread::spawn(move || {
                start.wait();
                match NativeSessionInventoryGuard::admit(&worker_root, admission, 0) {
                    Ok(guard) => drop(guard),
                    Err(error) => assert!(format!("{error:#}").contains("drain fence")),
                }
            });
            barrier.wait();
            let started = begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
            worker.join().unwrap();
            assert!(started.session_nonces.contains(&nonce));
            let finished = finish_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
            assert!(finished.checkpoint.is_complete());
            assert_eq!(finished.checkpoint.admitted_sessions, 1);
            assert_eq!(finished.checkpoint.terminal_sessions, 1);
            assert_eq!(
                finished.checkpoint.session_set_sha256,
                started.checkpoint.session_set_sha256
            );
        }
    }

    #[test]
    fn cooperative_stop_retains_final_ledger_after_reopening_without_certifying_quiescence() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let admission = fixture(&root, 30);
        let nonce = admission.session_nonce.clone();
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        guard.worker_started();
        guard.worker_reaped();
        guard.finish(
            NativeSessionOutcomeKind::ControlStopped,
            final_ledger_observation(),
        );
        drop(guard);

        let report = read_inventory_at(&root, None).unwrap();
        assert_eq!(report.pending_sessions, 0);
        assert_eq!(report.terminal_sessions, 1);
        assert_eq!(report.unknown_effect_sessions, 1);
        assert!(!report.quiescence_certified);
        assert_eq!(report.records[0].admission.session_nonce, nonce);
        let outcome = report.records[0].outcome.as_ref().unwrap();
        assert_eq!(outcome.kind, NativeSessionOutcomeKind::ControlStopped);
        assert_eq!(
            outcome.process,
            NativeSessionProcessObservation::WorkerReaped
        );
        assert_eq!(outcome.effects, final_ledger_observation());
        assert!(!outcome.containment_empty_observed);
    }

    #[test]
    fn signed_failed_attempts_remain_unknown_even_with_complete_terminal_accounting() {
        let mut effects = final_ledger_observation();
        assert!(effects.unknown());
        let NativeSessionEffectObservation::FinalLedgerObserved {
            failed_count,
            allowed_count,
            ..
        } = &mut effects
        else {
            unreachable!();
        };
        *failed_count = 0;
        *allowed_count += 1;
        assert!(!effects.unknown());
        assert!(NativeSessionEffectObservation::Unknown.unknown());
        assert!(!NativeSessionEffectObservation::NotStarted.unknown());
    }

    #[test]
    fn cooperative_stop_requires_both_worker_reap_and_final_ledger() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let admission = fixture(&root, 31);
        let guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        let mut outcome = NativeSessionOutcome {
            observed_at: Utc::now(),
            kind: NativeSessionOutcomeKind::ControlStopped,
            process: NativeSessionProcessObservation::Unproven,
            containment_empty_observed: false,
            effects: final_ledger_observation(),
        };
        assert!(guard.persist_outcome(&outcome).is_err());
        outcome.process = NativeSessionProcessObservation::WorkerReaped;
        outcome.effects = NativeSessionEffectObservation::Unknown;
        assert!(guard.persist_outcome(&outcome).is_err());
        assert!(
            read_inventory_at(&root, None).unwrap().records[0]
                .outcome
                .is_none()
        );
        outcome.effects = final_ledger_observation();
        guard.persist_outcome(&outcome).unwrap();
        assert_eq!(
            read_inventory_at(&root, None).unwrap().records[0].outcome,
            Some(outcome)
        );
    }

    #[test]
    fn hard_interruption_cannot_be_promoted_to_a_final_ledger_observation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let admission = fixture(&root, 32);
        let guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        let outcome = NativeSessionOutcome {
            observed_at: Utc::now(),
            kind: NativeSessionOutcomeKind::Interrupted,
            process: NativeSessionProcessObservation::WorkerReaped,
            containment_empty_observed: true,
            effects: final_ledger_observation(),
        };
        assert!(guard.persist_outcome(&outcome).is_err());
        let report = read_inventory_at(&root, None).unwrap();
        assert_eq!(report.pending_sessions, 1);
        assert_eq!(report.unknown_effect_sessions, 1);
        assert!(!report.quiescence_certified);
    }

    #[test]
    fn live_control_interruption_retains_complete_nonce_bound_unknown_effect_evidence() {
        use crate::ops::engine_dispatcher::{
            NativeEffectWalEntry, NativeRunControlKind, NativeRunControlTrigger,
        };
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let admission = fixture(&root, 27);
        let evidence = NativeEffectInterruptionEvidence {
            schema_version: NATIVE_EFFECT_INTERRUPTION_EVIDENCE_SCHEMA.to_string(),
            session_nonce: admission.session_nonce.clone(),
            terminal_state: "control_indeterminate".to_string(),
            replay_certified: false,
            journal_complete: true,
            journal_event_cap: NATIVE_SESSION_MAX_EFFECT_WAL_EVENTS,
            completed_effect_count: 1,
            interrupted_effect_count: 1,
            entries: vec![
                NativeEffectWalEntry {
                    sequence: 0,
                    effect_kind: "fs_read".to_string(),
                    request_hash: format!("sha256:{}", "a".repeat(64)),
                    state: NativeEffectWalState::ProviderReturned,
                },
                NativeEffectWalEntry {
                    sequence: 1,
                    effect_kind: "network_egress".to_string(),
                    request_hash: format!("sha256:{}", "b".repeat(64)),
                    state: NativeEffectWalState::InterruptedIndeterminate,
                },
            ],
            protocol_error: None,
            control_trigger: Some(NativeRunControlTrigger {
                kind: NativeRunControlKind::FleetPolicyChanged,
                detail: "current fleet limits require interruption".to_string(),
            }),
        };
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        guard.worker_started();
        guard.worker_reaped();
        let mut foreign = evidence.clone();
        foreign.session_nonce = uuid::Uuid::now_v7().to_string();
        let foreign_outcome = NativeSessionOutcome {
            observed_at: Utc::now(),
            kind: NativeSessionOutcomeKind::Interrupted,
            process: NativeSessionProcessObservation::WorkerReaped,
            containment_empty_observed: false,
            effects: NativeSessionEffectObservation::Interrupted {
                evidence: Box::new(foreign),
            },
        };
        assert!(guard.persist_outcome(&foreign_outcome).is_err());
        assert!(
            read_inventory_at(&root, None).unwrap().records[0]
                .outcome
                .is_none()
        );
        guard.finish(
            NativeSessionOutcomeKind::Interrupted,
            NativeSessionEffectObservation::Interrupted {
                evidence: Box::new(evidence.clone()),
            },
        );
        let report = read_inventory_at(&root, None).unwrap();
        assert_eq!(report.terminal_sessions, 1);
        assert_eq!(report.unknown_effect_sessions, 1);
        assert_eq!(
            report.records[0].outcome.as_ref().unwrap().effects,
            NativeSessionEffectObservation::Interrupted {
                evidence: Box::new(evidence)
            }
        );
        assert!(!report.quiescence_certified);
    }

    #[test]
    fn project_filter_cannot_hide_untracked_older_identity_captures() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let tracked = fixture(&root, 23);
        let old_project = tracked.project_root.clone();
        let _guard = NativeSessionInventoryGuard::admit(&root, tracked, 0).unwrap();
        let untracked = fixture(&root, 24);
        let report =
            read_inventory_at(&root, Some(&temp.path().join("different-project"))).unwrap();
        assert!(report.records.is_empty());
        assert_eq!(report.total_stored_sessions, 1);
        assert_eq!(report.untracked_identity_captures.len(), 1);
        assert_eq!(
            report.untracked_identity_captures[0].session_nonce,
            untracked.session_nonce
        );
        assert_eq!(
            read_inventory_at(&root, Some(&old_project))
                .unwrap()
                .pending_sessions,
            1
        );
    }

    #[test]
    fn admission_refuses_capture_epoch_mismatch_before_creating_inventory() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let mut admission = fixture(&root, 25);
        admission.security_epoch += 1;
        assert!(NativeSessionInventoryGuard::admit(&root, admission, 0).is_err());
        assert!(!root.join(INVENTORY_FILE).exists());
    }

    #[test]
    fn reservation_counts_utf8_bytes_and_rejection_rolls_back_without_eviction() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        ensure_runtime_evidence_directory(&root, true).unwrap();
        let connection = open_inventory(&root, true).unwrap().unwrap();
        {
            let tx = connection.transaction().unwrap();
            tx.execute_with_params(
                "INSERT INTO native_sessions(session_nonce, admission_json) VALUES ('test', ?1);",
                &[SqliteValue::Text("🦀".into())],
            )
            .unwrap();
            assert!(check_bounds_with_limits(&tx, 1, MAX_OUTCOME_BYTES + 1).is_err());
            check_bounds_with_limits(&tx, 1, MAX_OUTCOME_BYTES + "🦀".len()).unwrap();
            assert!(check_bounds_with_limits(&tx, 0, MAX_RESERVED_BYTES).is_err());
        }
        assert!(read_records(&connection).unwrap().is_empty());
    }

    #[test]
    fn impossible_persisted_terminal_claims_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let admission = fixture(&root, 26);
        let guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        let impossible = NativeSessionOutcome {
            observed_at: Utc::now(),
            kind: NativeSessionOutcomeKind::Completed,
            process: NativeSessionProcessObservation::NotSpawned,
            containment_empty_observed: true,
            effects: NativeSessionEffectObservation::Unknown,
        };
        assert!(guard.persist_outcome(&impossible).is_err());
        let mut tx = guard.connection.transaction().unwrap();
        tx.execute_with_params(
            "UPDATE native_sessions SET outcome_json = ?1 WHERE session_nonce = ?2;",
            &[
                SqliteValue::Text(serde_json::to_string(&impossible).unwrap().into()),
                SqliteValue::Text(admission.session_nonce.into()),
            ],
        )
        .unwrap();
        tx.commit().unwrap();
        assert!(read_records(&guard.connection).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_inventory_path_is_refused_before_creating_a_database() {
        use std::os::unix::ffi::OsStringExt as _;
        let temp = tempfile::tempdir().unwrap();
        let root = temp
            .path()
            .join(std::ffi::OsString::from_vec(b"state-\xff".to_vec()));
        ensure_runtime_evidence_directory(&root, true).unwrap();
        assert!(
            open_inventory(&root, true)
                .err()
                .expect("non-UTF-8 path must be refused")
                .to_string()
                .contains("lossy path alias")
        );
        assert!(!root.join(INVENTORY_FILE).exists());
    }

    #[cfg(unix)]
    #[test]
    fn sidecar_symlink_is_refused_without_touching_its_target() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        ensure_runtime_evidence_directory(&root, true).unwrap();
        let target = temp.path().join("untouched");
        std::fs::write(&target, b"sentinel").unwrap();
        symlink(&target, root.join(format!("{INVENTORY_FILE}-wal"))).unwrap();
        assert!(open_inventory(&root, true).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"sentinel");
    }
}
