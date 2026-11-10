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
    FleetActionRecord, FleetApplicationCheckpoint, NativeSessionDrainCheckpoint,
    fleet_action_snapshot_prefix, fleet_application_checkpoint, validate_node_id, validate_zone_id,
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
const MAX_DRAIN_BYTES: usize = (MAX_STORED_SESSIONS + MAX_IDENTITY_CAPTURES) * 68 + 64 * 1024;
const MAX_RETAINED_DRAINS: usize = crate::capacity_defaults::base::STANDARD;

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

fn admission_digest(admission: &NativeSessionAdmission) -> Result<String> {
    let bytes = bounded_json(admission, MAX_ADMISSION_BYTES)?;
    let mut digest = Sha256::new();
    digest.update(b"franken-node/native-session-admission/v1\0");
    digest.update(u64::try_from(bytes.len())?.to_be_bytes());
    digest.update(bytes.as_bytes());
    Ok(hex::encode(digest.finalize()))
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
        verify_admission_capture(protected_root, &admission)?;
        let admission_json = bounded_json(&admission, MAX_ADMISSION_BYTES)?;
        let connection = retry_snapshot_conflict(|| open_inventory(protected_root, true))?
            .context("native-session inventory was not created")?;
        let admitted = retry_snapshot_conflict(|| {
            let mut tx = connection.transaction()?;
            serialize_project_admission(&mut tx, &admission.project_root)?;
            let drain = latest_drain(&tx, &admission.project_root)?;
            let admitted = drain.as_ref().is_none_or(|drain| !drain.fence_held)
                && drain.as_ref().map_or(0, |drain| drain.generation) == expected_generation;
            // A race after identity provisioning must leave a known unspawned
            // outcome, rather than an untracked capture or an apparent worker.
            let outcome = if admitted {
                SqliteValue::Null
            } else {
                SqliteValue::Text(
                    bounded_json(
                        &NativeSessionOutcome {
                            observed_at: Utc::now(),
                            kind: NativeSessionOutcomeKind::SupervisionIncomplete,
                            process: NativeSessionProcessObservation::NotSpawned,
                            containment_empty_observed: false,
                            effects: NativeSessionEffectObservation::NotStarted,
                        },
                        MAX_OUTCOME_BYTES,
                    )?
                    .into(),
                )
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
    for nonce in &drain.session_nonces {
        uuid::Uuid::parse_str(nonce)?;
        if nonce.len() > 64 {
            bail!("native-session drain nonce exceeds its identity bound");
        }
    }
    drain.actions.validate()?;
    Ok(Some(drain))
}

fn admission_ticket_at(protected_root: &Path, project_root: &Path) -> Result<u64> {
    let Some(connection) = open_inventory(protected_root, false)? else {
        return Ok(0);
    };
    let mut tx = connection.transaction()?;
    let drain = latest_drain(&tx, project_root)?;
    tx.commit()?;
    if let Some(drain) = &drain
        && drain.fence_held
    {
        bail!(
            "native-session admission is fenced by local fleet drain {}",
            drain.drain_id
        );
    }
    Ok(drain.map_or(0, |drain| drain.generation))
}

/// Capture this before the final policy/trust recheck. Admission compares the
/// generation in the same transaction that records the worker obligation.
/// An active fence also makes the existing live observer cancel old workers.
pub(crate) fn native_session_admission_ticket(project_root: &Path) -> Result<u64> {
    let root = inventory_root()?;
    match std::fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error).context("inspect native-session admission fence"),
        Ok(_) => {}
    }
    ensure_runtime_evidence_directory(root.parent().context("missing product state root")?, true)?;
    ensure_runtime_evidence_directory(&root, true)?;
    admission_ticket_at(&root, project_root)
}

fn drain_report(
    drain: &StoredNativeSessionDrain,
    records: &[NativeSessionInventoryRecord],
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
        let Some(outcome) = &record.outcome else {
            pending += 1;
            continue;
        };
        let known_terminal = match (&outcome.process, &outcome.effects) {
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
                record.admission.process_spawn_authority_granted == Some(false)
                    || (record.admission.process_spawn_authority_granted == Some(true)
                        && outcome.containment_empty_observed)
            }
            _ => false,
        };
        if known_terminal {
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
        fleet_quiescence_certified: false,
    })
}

fn check_drain_owner(drain: &StoredNativeSessionDrain, node_id: &str, zone_id: &str) -> Result<()> {
    if drain.node_id != node_id || drain.zone_id != zone_id {
        bail!("retained native-session drain belongs to a different node/zone identity");
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
/// If a previous drain is still held, return that exact checkpoint unchanged:
/// the caller must reconcile its matching action-log prefix first. Never apply
/// a later release and silently discard an older unresolved population.
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
    let key = project_key(project_root)?;
    // Includes old identity captures with unknown projects. The transaction
    // below also includes every admission committed since this observation.
    let inventory = retry_snapshot_conflict(|| read_inventory_at(protected_root, None))?;
    let connection = retry_snapshot_conflict(|| open_inventory(protected_root, true))?
        .context("native-session drain inventory was not created")?;
    recover_retained_outcomes(protected_root, &connection, &inventory.records)?;
    retry_snapshot_conflict(|| {
        let mut tx = connection.transaction()?;
        serialize_project_admission(&mut tx, project_root)?;
        let previous = latest_drain(&tx, project_root)?;
        let records = read_records_in_transaction(&tx)?;
        if let Some(previous) = &previous {
            check_drain_owner(previous, node_id, zone_id)?;
            if previous.fence_held || previous.actions == *checkpoint {
                let report = drain_report(previous, &records)?;
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
            .filter(|record| record.admission.project_root == project_root)
            .map(|record| record.admission.session_nonce.clone())
            .chain(
                inventory
                    .untracked_identity_captures
                    .iter()
                    .map(|capture| capture.session_nonce.clone()),
            )
            .collect();
        let generation = previous
            .as_ref()
            .map_or(0, |drain| drain.generation)
            .checked_add(1)
            .context("native-session drain generation exhausted")?;
        let drain = StoredNativeSessionDrain {
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
        };
        let report = drain_report(&drain, &records)?;
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
/// Pending/unknown effects keep the durable fence held across restarts. A
/// completed report permits new admissions under freshly rechecked controls;
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
    retry_snapshot_conflict(|| {
        let mut tx = connection.transaction()?;
        serialize_project_admission(&mut tx, project_root)?;
        let mut drain =
            latest_drain(&tx, project_root)?.context("no retained native-session drain")?;
        check_drain_owner(&drain, node_id, zone_id)?;
        if drain.actions != *checkpoint {
            bail!("native-session drain completion requires its exact retained action checkpoint");
        }
        let records = read_records_in_transaction(&tx)?;
        let report = drain_report(&drain, &records)?;
        if drain.fence_held
            && report.checkpoint.pending_sessions == 0
            && report.checkpoint.indeterminate_sessions == 0
        {
            drain.fence_held = false;
            tx.execute_with_params(
                "UPDATE native_session_drains SET state_json = ?1 WHERE drain_id = ?2;",
                &[
                    SqliteValue::Text(bounded_json(&drain, MAX_DRAIN_BYTES)?.into()),
                    SqliteValue::Text(drain.drain_id.clone().into()),
                ],
            )?;
        }
        let report = drain_report(&drain, &records)?;
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
    let tracked: BTreeMap<_, _> = records
        .iter()
        .map(|record| (record.admission.session_nonce.clone(), &record.admission))
        .collect();
    let mut matched = BTreeSet::new();
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
                report
                    .untracked_identity_captures
                    .push(UntrackedNativeIdentityCapture {
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
    report
        .untracked_identity_captures
        .sort_by(|left, right| left.session_nonce.cmp(&right.session_nonce));
    for record in records {
        if report
            .project_root
            .as_ref()
            .is_some_and(|project| project != &record.admission.project_root)
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
        };
        let bytes = bounded_json(&drain, MAX_DRAIN_BYTES).unwrap();
        assert!(
            bytes.len() > 128 * 1024,
            "exercise the old accidental lower cap"
        );
        let decoded: StoredNativeSessionDrain = serde_json::from_str(&bytes).unwrap();
        assert_eq!(decoded.session_nonces, drain.session_nonces);
        let report = drain_report(&decoded, &[]).unwrap();
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
