//! Durable local observations of admitted native sessions.
//!
//! Admission is committed before the worker can start, in the existing
//! protected runtime-evidence subtree. A missing outcome remains pending after
//! restart: neither an expired deadline nor a reused/missing PID resolves it.
//! Outcomes describe what this supervisor observed, not a fleet barrier,
//! remote node attestation, rollback, or proof that external effects quiesced.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use fsqlite::compat::{Transaction, TransactionExt};
use fsqlite::{Connection, SqliteValue};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::engine_dispatcher::{
    HostEffectLedger, NATIVE_EFFECT_INTERRUPTION_EVIDENCE_SCHEMA,
    NATIVE_SESSION_MAX_DIAGNOSTIC_BYTES, NATIVE_SESSION_MAX_EFFECT_WAL_EVENTS,
    NATIVE_SESSION_MAX_EFFECT_WAL_STREAM_BYTES, NATIVE_SESSION_MAX_REQUEST_BYTES,
    NativeEffectInterruptionEvidence, NativeEffectWalState,
    RUNTIME_EVIDENCE_CAPTURE_DIR_RELATIVE_PATH, RUNTIME_EVIDENCE_PRODUCT_STATE_DIRECTORY,
    RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH, RUNTIME_EVIDENCE_STATE_DIRECTORY,
    RuntimeEvidenceIdentityCapture, create_new_runtime_evidence_private_file,
    ensure_runtime_evidence_directory, load_runtime_evidence_product_root,
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
// Reserve the maximum outcome for every pending admission. Recording a
// terminal/unknown outcome therefore remains possible at admission capacity.
const MAX_RESERVED_BYTES: usize = crate::capacity_defaults::base::SMALL * 1024 * 1024;

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

/// An owned supervisor obligation. Dropping this on an ordinary error records
/// only the observations already made. Process death bypasses Drop and leaves
/// the durable admission pending, which is deliberately never auto-resolved.
pub(crate) struct NativeSessionInventoryGuard {
    connection: Connection,
    session_nonce: String,
    process: NativeSessionProcessObservation,
    containment_empty_observed: bool,
    finished: bool,
}

impl NativeSessionInventoryGuard {
    pub(crate) fn admit(protected_root: &Path, admission: NativeSessionAdmission) -> Result<Self> {
        ensure_runtime_evidence_directory(protected_root, true)?;
        validate_admission(&admission)?;
        verify_admission_capture(protected_root, &admission)?;
        let admission_json = bounded_json(&admission, MAX_ADMISSION_BYTES)?;
        let connection = retry_snapshot_conflict(|| open_inventory(protected_root, true))?
            .context("native-session inventory was not created")?;
        retry_snapshot_conflict(|| {
            let mut tx = connection.transaction()?;
            tx.execute_with_params(
                "INSERT INTO native_sessions(session_nonce, admission_json, outcome_json)
                 VALUES (?1, ?2, NULL);",
                &[
                    SqliteValue::Text(admission.session_nonce.clone().into()),
                    SqliteValue::Text(admission_json.clone().into()),
                ],
            )?;
            check_bounds(&tx)?;
            tx.commit()?;
            Ok(())
        })
        .context("persist native-session admission before worker spawn")?;
        Ok(Self {
            connection,
            session_nonce: admission.session_nonce,
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
        let json = bounded_json(outcome, MAX_OUTCOME_BYTES)?;
        if let NativeSessionEffectObservation::Interrupted { evidence } = &outcome.effects
            && evidence.session_nonce != self.session_nonce
        {
            bail!("interruption evidence belongs to a different native session");
        }
        retry_snapshot_conflict(|| {
            let mut tx = self.connection.transaction()?;
            let rows = tx.query_with_params(
                "SELECT admission_json, outcome_json FROM native_sessions WHERE session_nonce = ?1;",
                &[SqliteValue::Text(self.session_nonce.clone().into())],
            )?;
            let [row] = rows.as_slice() else {
                bail!("native-session admission disappeared before outcome persistence");
            };
            let [admission, existing] = row.values() else {
                bail!("native-session outcome row shape is invalid");
            };
            let admission: NativeSessionAdmission = parse_json(admission, MAX_ADMISSION_BYTES)?;
            validate_admission(&admission)?;
            validate_outcome(&admission, outcome)?;
            match existing {
                SqliteValue::Null => {
                    tx.execute_with_params(
                        "UPDATE native_sessions SET outcome_json = ?1
                         WHERE session_nonce = ?2 AND outcome_json IS NULL;",
                        &[
                            SqliteValue::Text(json.clone().into()),
                            SqliteValue::Text(self.session_nonce.clone().into()),
                        ],
                    )?;
                }
                SqliteValue::Text(existing) if existing.as_ref() == json.as_str() => {}
                _ => bail!("native-session outcome is immutable once observed"),
            }
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
    check_bounds(&tx)?;
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
    tx.commit()?;
    Ok(records)
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
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission).unwrap();
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
        let mut guard = NativeSessionInventoryGuard::admit(&root, fixture(&root, 22)).unwrap();
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

    #[test]
    fn cooperative_stop_retains_final_ledger_after_reopening_without_certifying_quiescence() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let admission = fixture(&root, 30);
        let nonce = admission.session_nonce.clone();
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission).unwrap();
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
        let guard = NativeSessionInventoryGuard::admit(&root, admission).unwrap();
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
        let guard = NativeSessionInventoryGuard::admit(&root, admission).unwrap();
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
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission).unwrap();
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
        let _guard = NativeSessionInventoryGuard::admit(&root, tracked).unwrap();
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
        assert!(NativeSessionInventoryGuard::admit(&root, admission).is_err());
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
        let guard = NativeSessionInventoryGuard::admit(&root, admission.clone()).unwrap();
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
