//! Durable local observations of admitted native sessions.
//!
//! Admission is committed before the worker can start, in the existing
//! protected runtime-evidence subtree. A missing outcome remains pending after
//! restart: neither an expired deadline nor a reused/missing PID resolves it.
//! Outcomes describe what this supervisor observed, not a fleet barrier,
//! remote node attestation, rollback, or proof that external effects quiesced.
//! Before updating the inventory, a supervisor durably retains its signed
//! outcome. Fleet reconciliation and capacity-constrained admission may recover
//! that exact observation after a crash or failed database write; ordinary
//! inventory inspection stays read-only. New admissions also retain their exact
//! signed body outside the mutable database, so forensic evidence survives a
//! lost projection without changing admission or liveness authority.

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
    NativeSessionDrainCheckpoint, SeqlockControlPage, SeqlockControlSnapshot,
    fleet_action_snapshot_prefix, fleet_application_checkpoint, fleet_native_session_holds,
    validate_action_id, validate_node_id, validate_zone_id,
};

use super::engine_dispatcher::{
    HostEffectLedger, NATIVE_EFFECT_INTERRUPTION_EVIDENCE_SCHEMA,
    NATIVE_SESSION_MAX_DIAGNOSTIC_BYTES, NATIVE_SESSION_MAX_EFFECT_WAL_EVENTS,
    NATIVE_SESSION_MAX_EFFECT_WAL_STREAM_BYTES, NATIVE_SESSION_MAX_REQUEST_BYTES,
    NativeEffectInterruptionEvidence, NativeEffectWalEntry, NativeEffectWalState,
    RUNTIME_EVIDENCE_CAPTURE_DIR_RELATIVE_PATH, RUNTIME_EVIDENCE_PRODUCT_STATE_DIRECTORY,
    RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH, RUNTIME_EVIDENCE_STATE_DIRECTORY,
    RuntimeEvidenceIdentityCapture, create_new_runtime_evidence_private_file,
    ensure_runtime_evidence_directory, ensure_runtime_evidence_directory_with_status,
    load_or_create_runtime_evidence_product_root, load_runtime_evidence_product_root,
    prepare_runtime_evidence_directories, read_runtime_evidence_private_file,
    runtime_evidence_user_state_home, validate_runtime_evidence_private_file_metadata,
};

#[path = "native_session_lease.rs"]
mod supervisor_lease;

const INVENTORY_SCHEMA: &str = "franken-node/native-session-inventory/v1";
const FORENSIC_INVENTORY_SCHEMA: &str = "franken-node/native-session-forensic-inventory/v1";
const MAX_FORENSIC_DIAGNOSTIC_BYTES: usize = 4096;
const INVENTORY_FILE: &str = "native-sessions.db";
const RECOVER_CAPACITY_COMMAND: &str = "franken-node ops session-inventory recover --json";
const CAPACITY_QUERY: &str = "SELECT COUNT(*),
    COALESCE(SUM(CASE WHEN outcome_json IS NULL THEN 1 ELSE 0 END), 0),
    COALESCE(SUM(LENGTH(CAST(admission_json AS BLOB))
        + COALESCE(LENGTH(CAST(outcome_json AS BLOB)), 0)), 0)
    FROM native_sessions;";
const MAX_STORED_SESSIONS: usize = crate::capacity_defaults::base::STANDARD;
const MAX_IDENTITY_CAPTURES: usize = crate::capacity_defaults::base::LARGE;
// Do not introduce an accounting ceiling below the existing admitted request:
// identity strings can expand in JSON even within their raw 2MiB trust bound.
const MAX_ADMISSION_BYTES: usize = NATIVE_SESSION_MAX_REQUEST_BYTES;
const ADMISSION_RECEIPT_SCHEMA: &str = "franken-node/native-session-admission-receipt/v1";
const ADMISSION_RECEIPT_DIRECTORY: &str = "session-admissions";
const MAX_ADMISSION_RECEIPT_BYTES: usize = 4 * 1024;
const ADMISSION_RECORD_DIRECTORY: &str = "session-admission-records";
// Charge orphaned/partial publications too: a refused database insertion must
// not allow repeated admissions to grow the immutable evidence without bound.
const MAX_RETAINED_ADMISSION_BYTES: usize = crate::capacity_defaults::base::SMALL * 1024 * 1024;
const SOURCE_CAPSULE_DIRECTORY: &str = "session-source-capsules";
// Source retention has its own bounded allocation. Duplicate source capsules
// share one immutable object; orphaned/partial files still consume this budget.
#[cfg(unix)]
const MAX_RETAINED_SOURCE_CAPSULE_BYTES: usize =
    crate::capacity_defaults::base::SMALL * 1024 * 1024;
const MAX_OUTCOME_BYTES: usize =
    NATIVE_SESSION_MAX_EFFECT_WAL_STREAM_BYTES + NATIVE_SESSION_MAX_DIAGNOSTIC_BYTES;
const OUTCOME_RECEIPT_SCHEMA: &str = "franken-node/native-session-outcome-receipt/v1";
const OUTCOME_RECEIPT_DIRECTORY: &str = "session-outcomes";
const MAX_OUTCOME_RECEIPT_BYTES: usize = MAX_OUTCOME_BYTES + 1024;
// Retain useful panic diagnostics without allowing a large panic payload to
// displace the complete WAL or the mandatory signed terminal observation.
const MAX_PANIC_MESSAGE_BYTES: usize = 4096;
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
    /// Checked sum of this scope's and its ancestors' retained drain generations,
    /// captured before the final live authority recheck.
    pub admission_generation: u64,
    /// Exact additional owner's admitted policy, when one was present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fleet_policy_sha256: Option<String>,
}

/// Exact immutable inputs retained before a frozen worker may start. This
/// commitment is covered by the existing admission signature; it is not a
/// publisher endorsement or proof that the guest ran or its effects completed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSessionSourceCapsuleBinding {
    pub capsule_digest: String,
    pub graph_input_hash: String,
    pub capsule_bytes: usize,
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
    /// Historical and non-frozen admissions omit this. Omission preserves
    /// their original receipt preimages and never implies source retention.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_capsule: Option<NativeSessionSourceCapsuleBinding>,
}

impl NativeSessionAdmission {
    fn belongs_to_control_scope(&self, project_root: &Path) -> bool {
        self.project_root.starts_with(project_root)
            || self.control_scopes.as_ref().is_none_or(|scopes| {
                scopes
                    .iter()
                    .any(|scope| scope.project_root.starts_with(project_root))
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

/// Local checkpoints preserve their original signed observation. Enrolled
/// transports can explicitly request a new observation for their freshness
/// and evidence-withdrawal checks, without changing the retained population.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSessionDrainAttestationMode {
    /// Reuse unchanged historical evidence; elapsed time does not renew it.
    Retain,
    /// Sign a current observation without replacing unchanged local evidence.
    Refresh,
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
    /// Keep the complete signed observation so it can be authenticated before
    /// reuse or replacement, even when current accounting has since changed.
    /// This mutable observation is not part of the immutable census preimage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attested_checkpoint: Option<NativeSessionDrainCheckpoint>,
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
    /// The authenticated panic response followed complete reconciliation of
    /// an empty parent-observed host-effect journal, successful cleanup and
    /// explicit absence of process-spawn authority. A missing ledger alone
    /// never establishes this observation.
    NoAdmittedHostEffects,
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
            Self::NotStarted | Self::NoAdmittedHostEffects => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSessionPanicEvidence {
    /// A bounded UTF-8 prefix; the byte count and digest commit to the exact
    /// original message, including any suffix omitted from this diagnostic.
    pub panic_message: String,
    pub panic_message_bytes: usize,
    pub panic_message_sha256: String,
    pub panic_message_truncated: bool,
    pub cleanup_successful: bool,
    /// The reconciled parent-observed WAL, never a finalized effect ledger.
    /// Returned provider calls do not prove their external outcome or replay.
    pub host_effect_wal: Vec<NativeEffectWalEntry>,
}

impl NativeSessionPanicEvidence {
    pub(crate) fn from_validated_response(
        panic_message: &str,
        cleanup_successful: bool,
        host_effect_wal: Vec<NativeEffectWalEntry>,
    ) -> Self {
        let mut end = panic_message.len().min(MAX_PANIC_MESSAGE_BYTES);
        while !panic_message.is_char_boundary(end) {
            end -= 1;
        }
        Self {
            panic_message: panic_message[..end].to_owned(),
            panic_message_bytes: panic_message.len(),
            panic_message_sha256: hex::encode(Sha256::digest(panic_message.as_bytes())),
            panic_message_truncated: end < panic_message.len(),
            cleanup_successful,
            host_effect_wal,
        }
    }
}

fn deserialize_panic_evidence<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<NativeSessionPanicEvidence>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // Absence is the historical encoding. An explicit null, malformed value,
    // or unknown field must not disappear before signature verification.
    NativeSessionPanicEvidence::deserialize(deserializer).map(Some)
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
    /// Detailed panic evidence is part of the same signed outcome. Historical
    /// observations omit it, preserving their exact signed representation.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_panic_evidence"
    )]
    pub panic_evidence: Option<NativeSessionPanicEvidence>,
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

    #[cfg_attr(not(test), allow(dead_code))]
    fn issue(admission: &NativeSessionAdmission, root: &ed25519_dalek::SigningKey) -> Result<Self> {
        let verifying_key = root.verifying_key();
        Self::issue_with_verifying_key(admission, root, &verifying_key)
    }

    fn issue_with_verifying_key(
        admission: &NativeSessionAdmission,
        root: &ed25519_dalek::SigningKey,
        verifying_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<Self> {
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
        receipt.verify(admission, verifying_key)?;
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
    /// Preserve the exact compact JSON covered by the existing signature.
    /// Export this payload verbatim; a consumer must not reconstruct it from
    /// an untyped map whose key order may differ from the signing contract.
    fn payload_json(&self) -> Result<String> {
        #[derive(Serialize)]
        struct Payload<'a> {
            schema_version: &'a str,
            session_nonce: &'a str,
            product_root_key_id: &'a str,
            admission_sha256: &'a str,
            outcome: &'a NativeSessionOutcome,
        }

        bounded_json(
            &Payload {
                schema_version: &self.schema_version,
                session_nonce: &self.session_nonce,
                product_root_key_id: &self.product_root_key_id,
                admission_sha256: &self.admission_sha256,
                outcome: &self.outcome,
            },
            MAX_OUTCOME_RECEIPT_BYTES,
        )
    }

    fn preimage(&self) -> Result<Vec<u8>> {
        let payload = self.payload_json()?;
        let mut preimage = b"franken-node/native-session-outcome-signature/v1\0".to_vec();
        preimage.extend_from_slice(&u64::try_from(payload.len())?.to_be_bytes());
        preimage.extend_from_slice(payload.as_bytes());
        Ok(preimage)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn issue(
        admission: &NativeSessionAdmission,
        outcome: &NativeSessionOutcome,
        root: &ed25519_dalek::SigningKey,
    ) -> Result<Self> {
        let verifying_key = root.verifying_key();
        Self::issue_with_verifying_key(admission, outcome, root, &verifying_key)
    }

    fn issue_with_verifying_key(
        admission: &NativeSessionAdmission,
        outcome: &NativeSessionOutcome,
        root: &ed25519_dalek::SigningKey,
        verifying_key: &ed25519_dalek::VerifyingKey,
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
        receipt.verify(admission, verifying_key)?;
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

/// Exact database accounting, not a liveness or incident-clearance claim.
/// Pending rows reserve the largest admissible outcome even when the database
/// itself is small. Inspection never repairs a missing outcome projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSessionCapacityReport {
    pub schema_version: String,
    pub scope: String,
    pub database_path: PathBuf,
    pub store_present: bool,
    pub retained_sessions: usize,
    pub pending_null_outcomes: usize,
    pub actual_bytes: usize,
    pub reserved_bytes: usize,
    pub max_retained_sessions: usize,
    pub max_reserved_bytes: usize,
    /// Maximum of row and byte utilization, rounded up to a whole percent.
    pub pct_full: usize,
    pub capacity_exceeded: bool,
    pub recovery_command: String,
    pub quiescence_certified: bool,
}

impl NativeSessionCapacityReport {
    fn absent(protected_root: &Path) -> Self {
        Self {
            schema_version: "franken-node/native-session-capacity/v1".to_owned(),
            scope: "local_inventory_accounting_not_liveness".to_owned(),
            database_path: protected_root.join(INVENTORY_FILE),
            store_present: false,
            retained_sessions: 0,
            pending_null_outcomes: 0,
            actual_bytes: 0,
            reserved_bytes: 0,
            max_retained_sessions: MAX_STORED_SESSIONS,
            max_reserved_bytes: MAX_RESERVED_BYTES,
            pct_full: 0,
            capacity_exceeded: false,
            recovery_command: RECOVER_CAPACITY_COMMAND.to_owned(),
            quiescence_certified: false,
        }
    }
}

/// Repair of the database's projection of already signed supervisor outcomes.
/// No receipt is created, no session is removed, and no fleet fence is released.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSessionCapacityRecoveryReport {
    pub schema_version: String,
    pub scope: String,
    pub recovered_sessions: usize,
    pub reclaimed_reserved_bytes: usize,
    pub before: NativeSessionCapacityReport,
    pub after: NativeSessionCapacityReport,
    pub quiescence_certified: bool,
}

/// Authentication status of a retained supervisor observation. A pending
/// admission does not establish whether a worker is alive or was interrupted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSessionForensicStatus {
    PendingLivenessUnknown,
    TerminalObservation,
    SupervisionIncomplete,
    OutcomeUnverified,
}

impl NativeSessionForensicStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PendingLivenessUnknown => "pending_liveness_unknown",
            Self::TerminalObservation => "terminal_observation",
            Self::SupervisionIncomplete => "supervision_incomplete",
            Self::OutcomeUnverified => "outcome_unverified",
        }
    }
}

/// Both admission identity and scope are authenticated before inclusion.
/// An outcome requires its original supervisor receipt or the product-signed
/// cold archive that retained that authenticated observation before retirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSessionForensicRecord {
    pub admission: NativeSessionAdmission,
    pub outcome: Option<NativeSessionOutcome>,
    pub status: NativeSessionForensicStatus,
    /// The signed admission receipt or authenticated cold archive containing it.
    pub admission_receipt_path: PathBuf,
    /// The signed outcome receipt or authenticated cold archive containing it.
    pub outcome_receipt_path: Option<PathBuf>,
    /// The signed observation was absent from the database projection. This
    /// includes cold evidence; inspection never repairs or repopulates the store.
    pub outcome_recovered_from_receipt: bool,
    /// Independently authenticated provider observations never promote a
    /// pending launch to a terminal session or establish worker liveness.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durable_journal: Option<NativeSessionForensicJournal>,
}

/// Owned report fields preserve the existing deserializable inventory API.
/// Only the SDK verifier constructs this observation during discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSessionForensicJournal {
    pub schema_version: String,
    pub scope: String,
    pub record_count: usize,
    pub event_count: usize,
    pub admitted_provider_calls: usize,
    pub returned_provider_calls: usize,
    pub indeterminate_provider_calls: usize,
    pub head_record_sha256: String,
    pub trailing_partial_record: bool,
    pub replay_certified: bool,
    pub quiescence_certified: bool,
    pub historical_completeness: bool,
}

impl From<frankenengine_verifier_sdk::native_session::VerifiedNativeSessionEffectJournal>
    for NativeSessionForensicJournal
{
    fn from(
        journal: frankenengine_verifier_sdk::native_session::VerifiedNativeSessionEffectJournal,
    ) -> Self {
        Self {
            schema_version: journal.schema_version.to_owned(),
            scope: journal.scope.to_owned(),
            record_count: journal.record_count,
            event_count: journal.event_count,
            admitted_provider_calls: journal.admitted_provider_calls,
            returned_provider_calls: journal.returned_provider_calls,
            indeterminate_provider_calls: journal.indeterminate_provider_calls,
            head_record_sha256: journal.head_record_sha256,
            trailing_partial_record: journal.trailing_partial_record,
            replay_certified: journal.replay_certified,
            quiescence_certified: journal.quiescence_certified,
            historical_completeness: journal.historical_completeness,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSessionForensicErrorKind {
    InventoryUnreadable,
    AdmissionInvalid,
    AdmissionRecordInvalid,
    IdentityInvalid,
    AdmissionReceiptMissing,
    AdmissionReceiptInvalid,
    OutcomeReceiptMissing,
    OutcomeReceiptInvalid,
    OutcomeProjectionConflict,
    JournalInvalid,
    SourceCapsuleInvalid,
    IdentityInventoryInvalid,
    ColdArchiveInvalid,
}

/// Source failures are separate from authenticated records. A nonce here is
/// only a bounded lookup selector, never an authenticated session identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSessionForensicSourceError {
    pub session_nonce: Option<String>,
    pub path: PathBuf,
    pub kind: NativeSessionForensicErrorKind,
    pub detail: String,
}

impl std::fmt::Display for NativeSessionForensicSourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.path.display(), self.detail)
    }
}

impl std::error::Error for NativeSessionForensicSourceError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSessionForensicReport {
    pub schema_version: String,
    pub scope: String,
    pub coverage: String,
    pub database_path: PathBuf,
    pub store_present: bool,
    pub project_root: Option<PathBuf>,
    pub records: Vec<NativeSessionForensicRecord>,
    pub source_errors: Vec<NativeSessionForensicSourceError>,
    pub untracked_identity_captures: Vec<UntrackedNativeIdentityCapture>,
    pub replay_certified: bool,
    pub quiescence_certified: bool,
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
    project_key(&admission.project_root)?;
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
    if let Some(source) = &admission.source_capsule {
        validate_source_capsule_binding(source)?;
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

fn validate_source_capsule_binding(source: &NativeSessionSourceCapsuleBinding) -> Result<()> {
    use frankenengine_verifier_sdk::native_session::MAX_NATIVE_SESSION_SOURCE_CAPSULE_BYTES;

    if !source
        .capsule_digest
        .strip_prefix("sha256:")
        .is_some_and(valid_digest)
        || !source
            .graph_input_hash
            .strip_prefix("sha256:")
            .is_some_and(valid_digest)
        || !(12..=MAX_NATIVE_SESSION_SOURCE_CAPSULE_BYTES).contains(&source.capsule_bytes)
    {
        bail!("native-session source capsule binding has an invalid digest or byte bound");
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

    if let Some(evidence) = &outcome.panic_evidence {
        if outcome.kind != Kind::Panicked
            || evidence.panic_message.len() > MAX_PANIC_MESSAGE_BYTES
            || evidence.panic_message_bytes < evidence.panic_message.len()
            || evidence.panic_message_truncated
                != (evidence.panic_message_bytes > evidence.panic_message.len())
            || (evidence.panic_message_truncated
                && evidence.panic_message_bytes <= MAX_PANIC_MESSAGE_BYTES)
            || !valid_digest(&evidence.panic_message_sha256)
            || (!evidence.panic_message_truncated
                && evidence.panic_message_sha256
                    != hex::encode(Sha256::digest(evidence.panic_message.as_bytes())))
            || evidence
                .host_effect_wal
                .len()
                .checked_mul(2)
                .is_none_or(|events| events > NATIVE_SESSION_MAX_EFFECT_WAL_EVENTS)
        {
            bail!("native-session panic evidence is inconsistent");
        }
        // A validated Panicked response arrives only after the supervisor has
        // rejected incomplete, out-of-order, or mismatched WAL frames. Never
        // broaden this evidence type to generic worker or protocol failures.
        for (sequence, entry) in evidence.host_effect_wal.iter().enumerate() {
            if entry.sequence != u64::try_from(sequence)?
                || entry.state != NativeEffectWalState::ProviderReturned
                || entry.effect_kind.trim().is_empty()
                || !entry
                    .request_hash
                    .strip_prefix("sha256:")
                    .is_some_and(valid_digest)
            {
                bail!("native-session panic WAL entry is inconsistent");
            }
        }
        bounded_json(
            &evidence.host_effect_wal,
            NATIVE_SESSION_MAX_EFFECT_WAL_STREAM_BYTES,
        )
        .context("native-session panic WAL exceeds its retained byte bound")?;
        if outcome.effects == Effects::NoAdmittedHostEffects
            && (!evidence.cleanup_successful || !evidence.host_effect_wal.is_empty())
        {
            bail!("native-session no-effects panic contradicts its retained evidence");
        }
    }
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
        Effects::NoAdmittedHostEffects => {
            if outcome.kind != Kind::Panicked
                || outcome.process != Process::WorkerReaped
                || admission.process_spawn_authority_granted != Some(false)
            {
                bail!(
                    "native-session no-effects panic requires a reaped worker without process authority"
                );
            }
        }
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
                        | "worker_exit_indeterminate"
                        | "timeout_cleanup_unproven"
                        | "control_cleanup_unproven"
                        | "worker_exit_cleanup_unproven"
                )
                || (evidence.terminal_state.starts_with("worker_exit_")
                    && outcome.process != Process::WorkerReaped)
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

#[cfg_attr(not(test), allow(dead_code))]
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
    let product_root = load_runtime_evidence_product_root(
        &protected_root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH),
    )?;
    verify_admission_capture_with_root(protected_root, admission, &product_root.verifying_key())
}

/// Check retained identity bytes without provisioning directories or changing
/// their permissions. The caller validates the existing protected namespace.
fn verify_admission_capture_with_root(
    protected_root: &Path,
    admission: &NativeSessionAdmission,
    product_root: &ed25519_dalek::VerifyingKey,
) -> Result<()> {
    let capture_directory = protected_root.join(RUNTIME_EVIDENCE_CAPTURE_DIR_RELATIVE_PATH);
    if admission.identity_capture_path.parent() != Some(capture_directory.as_path()) {
        bail!("native-session capture is outside its protected capture directory");
    }
    let bytes = read_runtime_evidence_private_file(&admission.identity_capture_path, 64 * 1024)?;
    let capture: RuntimeEvidenceIdentityCapture = serde_json::from_slice(&bytes)?;
    verify_capture_for_admission(admission, &capture, product_root)
}

fn verify_capture_for_admission(
    admission: &NativeSessionAdmission,
    capture: &RuntimeEvidenceIdentityCapture,
    product_root: &ed25519_dalek::VerifyingKey,
) -> Result<()> {
    capture.verify_with_product_root(product_root)?;
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
    let (count, bytes) = inventory_reservation_usage(tx)?;
    check_reservation_usage(count, bytes, max_records, max_bytes)
}

fn check_reservation_usage(
    count: usize,
    bytes: usize,
    max_records: usize,
    max_bytes: usize,
) -> Result<()> {
    if count > max_records || bytes > max_bytes {
        tracing::warn!(
            event_code = "NSI_CAPACITY_DENIED",
            retained_sessions = count,
            reserved_bytes = bytes,
            max_retained_sessions = max_records,
            max_reserved_bytes = max_bytes,
            recovery_command = RECOVER_CAPACITY_COMMAND,
            "native-session admission capacity exhausted"
        );
        bail!(
            "native-session inventory capacity exceeded: {count}/{max_records} retained sessions, \
             {bytes}/{max_bytes} reserved bytes; refusing to discard retained sessions; \
             inspect_command=`franken-node ops session-inventory status --json`; \
             fix_command=`{RECOVER_CAPACITY_COMMAND}` (existing signed outcomes only; \
             unsigned pending sessions require investigation)"
        );
    }
    Ok(())
}

fn inventory_reservation_usage(tx: &Transaction<'_>) -> Result<(usize, usize)> {
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
    Ok((count, bytes))
}

fn validate_private_path_metadata_if_present(path: &Path) -> Result<Option<std::fs::Metadata>> {
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
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

fn validate_private_path_if_present(path: &Path) -> Result<bool> {
    Ok(validate_private_path_metadata_if_present(path)?.is_some())
}

#[cfg(unix)]
fn source_capsule_path(
    protected_root: &Path,
    binding: &NativeSessionSourceCapsuleBinding,
) -> Result<PathBuf> {
    validate_source_capsule_binding(binding)?;
    let digest = binding
        .capsule_digest
        .strip_prefix("sha256:")
        .context("native-session source capsule digest has no prefix")?;
    Ok(protected_root
        .join(SOURCE_CAPSULE_DIRECTORY)
        .join(format!("{digest}.fnsgcap")))
}

fn check_private_directory_capacity(
    directory: &Path,
    additional_files: usize,
    additional_bytes: usize,
    max_files: usize,
    max_bytes: usize,
    item_kind: &str,
    plural_kind: &str,
) -> Result<()> {
    let mut files = additional_files;
    let mut bytes = additional_bytes;
    #[cfg(unix)]
    {
        use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, fstat, open, statat};

        let expected_uid = rustix::process::geteuid().as_raw();
        let dir_fd = open(
            directory,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("open retained native-session {plural_kind} directory"))?;
        let dir_stat = fstat(&dir_fd)
            .with_context(|| format!("inspect retained native-session {plural_kind} directory"))?;
        if FileType::from_raw_mode(dir_stat.st_mode) != FileType::Directory
            || dir_stat.st_uid != expected_uid
            || (dir_stat.st_mode & 0o077) != 0
        {
            bail!("retained native-session {plural_kind} directory must be private and owned");
        }
        let dir_iter = Dir::read_from(&dir_fd)
            .with_context(|| format!("enumerate retained native-session {plural_kind}"))?;
        for entry in dir_iter {
            let entry = entry
                .with_context(|| format!("enumerate retained native-session {plural_kind}"))?;
            let name = entry.file_name();
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            let stat = match statat(&dir_fd, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => stat,
                Err(rustix::io::Errno::NOENT) => {
                    bail!(
                        "retained native-session {item_kind} disappeared during capacity accounting"
                    );
                }
                Err(error) => {
                    return Err(std::io::Error::from(error))
                        .with_context(|| format!("inspect retained native-session {item_kind}"));
                }
            };
            let file_type = FileType::from_raw_mode(stat.st_mode);
            if file_type == FileType::Symlink {
                bail!(
                    "native-session inventory path {} is a symlink",
                    name.to_string_lossy()
                );
            }
            if file_type != FileType::RegularFile {
                bail!(
                    "runtime evidence key material {} must be a regular file",
                    name.to_string_lossy()
                );
            }
            if (stat.st_mode & 0o077) != 0 {
                bail!(
                    "runtime evidence key material {} must not grant group or other access",
                    name.to_string_lossy()
                );
            }
            if stat.st_nlink != 1 || stat.st_uid != expected_uid {
                bail!("native-session inventory file must be owned and have a single link");
            }
            let len = u64::try_from(stat.st_size)
                .context("retained native-session file reported negative size")?;
            files = files.saturating_add(1);
            bytes = bytes.saturating_add(usize::try_from(len)?);
            if files > max_files || bytes > max_bytes {
                bail!(
                    "native-session {item_kind} capacity exceeded: {files}/{max_files} retained \
                     files, {bytes}/{max_bytes} bytes; refusing to discard retained {plural_kind}"
                );
            }
        }
    }
    #[cfg(not(unix))]
    {
        for entry in std::fs::read_dir(directory)
            .with_context(|| format!("enumerate retained native-session {plural_kind}"))?
        {
            let path = entry?.path();
            let Some(metadata) = validate_private_path_metadata_if_present(&path)? else {
                bail!("retained native-session {item_kind} disappeared during capacity accounting");
            };
            files = files.saturating_add(1);
            bytes = bytes.saturating_add(usize::try_from(metadata.len())?);
            if files > max_files || bytes > max_bytes {
                bail!(
                    "native-session {item_kind} capacity exceeded: {files}/{max_files} retained \
                     files, {bytes}/{max_bytes} bytes; refusing to discard retained {plural_kind}"
                );
            }
        }
    }
    if files > max_files || bytes > max_bytes {
        bail!("native-session {item_kind} capacity exceeded before retention");
    }
    Ok(())
}

#[cfg(unix)]
fn check_source_capsule_capacity(
    directory: &Path,
    additional_files: usize,
    additional_bytes: usize,
    max_files: usize,
    max_bytes: usize,
) -> Result<()> {
    check_private_directory_capacity(
        directory,
        additional_files,
        additional_bytes,
        max_files,
        max_bytes,
        "source capsule",
        "sources",
    )
}

/// Proof returned by [`retain_native_session_source_capsule_with_proof`]
/// attesting that the encoded `FNSGCAP1` capsule for a freshly captured
/// `CapturedModuleGraph` was just created or verified byte-for-byte on disk.
///
/// The private fields prevent external construction; `admit_with_context_inner`
/// still re-checks directory safety and `(dev, ino, len, mtime, mtime_nsec)`
/// plus owner/mode metadata on disk before skipping the redundant full
/// `capsule::replay` re-parse, falling back to full replay on any discrepancy.
#[cfg(unix)]
pub(crate) struct RetainedNativeSessionSourceCapsule {
    protected_root: PathBuf,
    binding: NativeSessionSourceCapsuleBinding,
    encoded: crate::supply_chain::module_resolution_graph::file_resolution::source_graph::capsule::EncodedCapsule,
    capsule_path: PathBuf,
    entrypoint: String,
    file_identity: (u64, u64, u64, i64, i64),
}

#[cfg(unix)]
impl RetainedNativeSessionSourceCapsule {
    pub(crate) fn binding(&self) -> &NativeSessionSourceCapsuleBinding {
        &self.binding
    }

    pub(crate) fn encoded_capsule(
        &self,
    ) -> &crate::supply_chain::module_resolution_graph::file_resolution::source_graph::capsule::EncodedCapsule
{
        &self.encoded
    }

    fn verify_on_disk(&self, protected_root: &Path, admission: &NativeSessionAdmission) -> bool {
        use std::os::unix::fs::MetadataExt as _;

        if self.protected_root != protected_root
            || admission.source_capsule.as_ref() != Some(&self.binding)
        {
            return false;
        }
        let Ok(rel_entry) = admission.entrypoint.strip_prefix(&admission.project_root) else {
            return false;
        };
        if rel_entry.to_str() != Some(self.entrypoint.as_str()) {
            return false;
        }
        if validate_existing_forensic_directory(&protected_root.join(SOURCE_CAPSULE_DIRECTORY))
            .is_err()
        {
            return false;
        }
        let Ok(metadata) = std::fs::symlink_metadata(&self.capsule_path) else {
            return false;
        };
        if metadata.file_type().is_symlink()
            || validate_runtime_evidence_private_file_metadata(&self.capsule_path, &metadata)
                .is_err()
        {
            return false;
        }
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
        ) == self.file_identity
    }
}

#[cfg(not(unix))]
pub(crate) struct RetainedNativeSessionSourceCapsule;

#[cfg(not(unix))]
impl RetainedNativeSessionSourceCapsule {
    fn verify_on_disk(&self, _protected_root: &Path, _admission: &NativeSessionAdmission) -> bool {
        false
    }
}

/// Persist the existing source-capsule format before admission. Publication is
/// no-clobber and serialized with inventory writers, including capacity checks.
/// A reused object must match byte-for-byte; damaged retained evidence is never
/// silently replaced by recapturing a live project.
#[cfg(unix)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn retain_native_session_source_capsule(
    protected_root: &Path,
    graph: &crate::supply_chain::module_resolution_graph::file_resolution::source_graph::CapturedModuleGraph,
) -> Result<NativeSessionSourceCapsuleBinding> {
    retain_native_session_source_capsule_with_proof(protected_root, graph)
        .map(|retained| retained.binding)
}

#[cfg(unix)]
pub(crate) fn retain_native_session_source_capsule_with_proof(
    protected_root: &Path,
    graph: &crate::supply_chain::module_resolution_graph::file_resolution::source_graph::CapturedModuleGraph,
) -> Result<RetainedNativeSessionSourceCapsule> {
    use crate::supply_chain::module_resolution_graph::file_resolution::source_graph::capsule;
    use std::os::unix::fs::MetadataExt as _;

    let encoded =
        capsule::encode(graph).context("encode admitted native-session source capsule")?;
    let binding = NativeSessionSourceCapsuleBinding {
        capsule_digest: encoded.digest().to_owned(),
        graph_input_hash: graph.report().input_hash.clone(),
        capsule_bytes: encoded.bytes().len(),
    };
    validate_source_capsule_binding(&binding)?;
    ensure_runtime_evidence_directory(protected_root, true)?;
    let directory = protected_root.join(SOURCE_CAPSULE_DIRECTORY);
    let created_directory = ensure_runtime_evidence_directory_with_status(&directory, true)?;
    let _write_lock = lock_inventory_file(protected_root, true)?;
    let path = source_capsule_path(protected_root, &binding)?;
    let exists = validate_private_path_if_present(&path)?;
    check_source_capsule_capacity(
        &directory,
        usize::from(!exists),
        if exists { 0 } else { encoded.bytes().len() },
        MAX_STORED_SESSIONS,
        MAX_RETAINED_SOURCE_CAPSULE_BYTES,
    )?;
    let created_capsule = if !exists {
        create_new_runtime_evidence_private_file(&path, encoded.bytes())?
    } else {
        false
    };
    if !created_capsule {
        // Re-read through the same private, no-follow reader used by forensics.
        // This also rejects a conflicting object that raced publication.
        if !validate_private_path_if_present(&path)? {
            bail!("native-session source capsule disappeared after retention");
        }
        let retained = read_runtime_evidence_private_file(&path, capsule::MAX_CAPSULE_BYTES)?;
        if retained.as_slice() != encoded.bytes() {
            bail!("retained native-session source capsule conflicts with the admitted capture");
        }
    }
    if created_directory {
        std::fs::File::open(protected_root)?.sync_all()?;
    }
    let metadata = std::fs::symlink_metadata(&path)
        .context("inspect retained native-session source capsule identity")?;
    validate_runtime_evidence_private_file_metadata(&path, &metadata)?;
    let file_identity = (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
    );
    Ok(RetainedNativeSessionSourceCapsule {
        protected_root: protected_root.to_path_buf(),
        binding,
        encoded,
        capsule_path: path,
        entrypoint: graph.report().entrypoint.clone(),
        file_identity,
    })
}

/// Validate retained bytes against the original admission, without reading any
/// live project path or repairing the evidence store. Capsule replay here only
/// reconstructs source analysis; it does not execute or replay guest effects.
fn read_retained_native_session_source_capsule(
    protected_root: &Path,
    admission: &NativeSessionAdmission,
) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
    let Some(binding) = &admission.source_capsule else {
        return Ok(None);
    };
    validate_source_capsule_binding(binding)?;
    #[cfg(not(unix))]
    {
        let _ = protected_root;
        bail!("retained native-session source verification requires Unix");
    }
    #[cfg(unix)]
    {
        use crate::supply_chain::module_resolution_graph::file_resolution::source_graph::capsule;

        validate_existing_forensic_directory(&protected_root.join(SOURCE_CAPSULE_DIRECTORY))?;
        let path = source_capsule_path(protected_root, binding)?;
        if !validate_private_path_if_present(&path)? {
            bail!("native-session admission source capsule is missing");
        }
        let bytes = read_runtime_evidence_private_file(&path, capsule::MAX_CAPSULE_BYTES)?;
        if bytes.len() != binding.capsule_bytes {
            bail!("retained native-session source capsule length disagrees with admission");
        }
        let graph = capsule::replay(&bytes, &binding.capsule_digest)
            .context("authenticate retained native-session source capsule")?;
        let entrypoint = admission
            .entrypoint
            .strip_prefix(&admission.project_root)
            .context("native-session source entrypoint escapes its admitted project")?
            .to_str()
            .context("native-session source entrypoint is not UTF-8")?;
        if graph.report().input_hash != binding.graph_input_hash
            || graph.report().entrypoint != entrypoint
        {
            bail!("retained native-session sources disagree with the admitted graph or entrypoint");
        }
        Ok(Some(bytes))
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
        if (opened.permissions().mode() & 0o7777) != 0o600 {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            validate_runtime_evidence_private_file_metadata(path, &file.metadata()?)?;
        } else {
            validate_runtime_evidence_private_file_metadata(path, &opened)?;
        }
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

#[cfg(unix)]
fn lock_file_identity(file: Option<&std::fs::File>) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file?.metadata().ok()?;
    Some((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn lock_file_identity(_file: Option<&std::fs::File>) -> Option<(u64, u64)> {
    None
}

fn lock_inventory_file(protected_root: &Path, create: bool) -> Result<Option<std::fs::File>> {
    let database_path = protected_root.join(INVENTORY_FILE);
    database_path
        .to_str()
        .context("native-session inventory path must be UTF-8; refusing a lossy path alias")?;
    let observed = match validate_private_path_metadata_if_present(&database_path)? {
        Some(metadata) => metadata,
        None => {
            if !create {
                return Ok(None);
            }
            create_new_runtime_evidence_private_file(&database_path, &[])?;
            validate_private_path_metadata_if_present(&database_path)?
                .context("native-session inventory disappeared after creation")?
        }
    };
    #[cfg(unix)]
    let file = {
        use rustix::fs::{Mode, OFlags, open};
        use std::os::unix::fs::MetadataExt as _;
        let file = std::fs::File::from(open(
            &database_path,
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let opened = file.metadata()?;
        if observed.dev() != opened.dev()
            || observed.ino() != opened.ino()
            || opened.nlink() != 1
            || opened.uid() != rustix::process::geteuid().as_raw()
        {
            bail!("native-session inventory lock target identity changed");
        }
        validate_runtime_evidence_private_file_metadata(&database_path, &opened)?;
        file
    };
    #[cfg(not(unix))]
    let file = {
        validate_runtime_evidence_private_file_metadata(&database_path, &observed)?;
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&database_path)?
    };
    file.lock()
        .context("acquire native-session inventory write lock")?;
    Ok(Some(file))
}

fn open_inventory(protected_root: &Path, create: bool) -> Result<Option<Connection>> {
    let _write_lock = if create {
        lock_inventory_file(protected_root, true)?
    } else {
        None
    };
    open_inventory_unlocked(protected_root, create)
}

#[cfg(unix)]
fn path_file_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::symlink_metadata(path).ok()?;
    Some((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn path_file_identity(_path: &Path) -> Option<(u64, u64)> {
    None
}

fn inventory_tables_present(tx: &Transaction<'_>) -> Result<(bool, bool)> {
    let rows = tx.query(
        "SELECT name FROM sqlite_master
         WHERE type = 'table'
           AND name IN (
               'native_sessions',
               'native_session_drains',
               'native_session_admission_serialization'
           );",
    )?;
    let mut count = 0_usize;
    let mut has_drains = false;
    for row in rows {
        if let [SqliteValue::Text(name)] = row.values() {
            count += 1;
            if name.as_ref() == "native_session_drains" {
                has_drains = true;
            }
        }
    }
    Ok((count == 3, has_drains))
}

fn inventory_schema_is_current(connection: &Connection) -> bool {
    connection
        .query(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'table'
               AND name IN (
                   'native_sessions',
                   'native_session_drains',
                   'native_session_admission_serialization'
               );",
        )
        .is_ok_and(|rows| {
            matches!(
                rows.as_slice(),
                [row] if matches!(row.values(), [SqliteValue::Integer(3)])
            )
        })
}

fn ensure_inventory_schema(connection: &Connection) -> Result<()> {
    if !inventory_schema_is_current(connection) {
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
    Ok(())
}

fn open_inventory_unlocked(protected_root: &Path, create: bool) -> Result<Option<Connection>> {
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
    let connection = retry_snapshot_conflict(|| {
        protect_sidecars(protected_root)?;
        let connection =
            Connection::open(database_name).context("open protected native-session inventory")?;
        for pragma in [
            "PRAGMA busy_timeout=5000;",
            "PRAGMA journal_mode=WAL;",
            "PRAGMA synchronous=FULL;",
        ] {
            connection
                .query(pragma)
                .context("configure native-session inventory durability")?;
        }
        if create {
            ensure_inventory_schema(&connection)?;
        }
        protect_sidecars(protected_root)?;
        Ok(connection)
    })?;
    Ok(Some(connection))
}

fn retry_snapshot_conflict<T>(mut operation: impl FnMut() -> Result<T>) -> Result<T> {
    let pid_jitter_ms = u64::from(std::process::id() % 17);
    for attempt in 0..10_u32 {
        match operation() {
            Err(error) if attempt < 9 => {
                let message = format!("{error:#}").to_ascii_lowercase();
                if !message.contains("snapshot conflict")
                    && !message.contains("database is busy")
                    && !message.contains("database is locked")
                {
                    return Err(error);
                }
                let base_ms = 15_u64 << attempt.min(5);
                std::thread::sleep(std::time::Duration::from_millis(base_ms + pid_jitter_ms));
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

fn admission_record_path(protected_root: &Path, nonce: &str) -> PathBuf {
    protected_root
        .join(ADMISSION_RECORD_DIRECTORY)
        .join(format!(
            "{}.json",
            hex::encode(Sha256::digest(nonce.as_bytes()))
        ))
}

/// Read the exact admitted body through the original receipt and identity
/// capture. Older admissions may lack this object; no forensic reader creates
/// it from the database or repairs an invalid retained object.
fn read_retained_admission_record(
    protected_root: &Path,
    nonce: &str,
    trusted_root: &ed25519_dalek::VerifyingKey,
) -> Result<Option<(NativeSessionAdmission, NativeSessionAdmissionReceipt)>> {
    let directory = protected_root.join(ADMISSION_RECORD_DIRECTORY);
    match std::fs::symlink_metadata(&directory) {
        Ok(_) => validate_existing_forensic_directory(&directory)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect retained native-session admissions"),
    }
    let path = admission_record_path(protected_root, nonce);
    if !validate_private_path_if_present(&path)? {
        return Ok(None);
    }
    let bytes = read_runtime_evidence_private_file(&path, MAX_ADMISSION_BYTES)?;
    let admission: NativeSessionAdmission = serde_json::from_slice(&bytes)
        .context("decode retained native-session admission record")?;
    validate_admission(&admission)?;
    if admission.session_nonce != nonce {
        bail!("retained native-session admission record has a different nonce");
    }
    if bounded_json(&admission, MAX_ADMISSION_BYTES)?.as_bytes() != bytes.as_slice() {
        bail!("retained native-session admission record is not the exact canonical body");
    }
    validate_existing_forensic_directory(
        &protected_root.join(RUNTIME_EVIDENCE_CAPTURE_DIR_RELATIVE_PATH),
    )?;
    validate_existing_forensic_directory(&protected_root.join(ADMISSION_RECEIPT_DIRECTORY))?;
    verify_admission_capture_with_root(protected_root, &admission, trusted_root)?;
    let receipt = read_admission_receipt(protected_root, &admission, trusted_root)?
        .context("retained native-session admission record has no authenticated receipt")?;
    Ok(Some((admission, receipt)))
}

fn check_admission_record_capacity(
    directory: &Path,
    additional_files: usize,
    additional_bytes: usize,
    max_files: usize,
    max_bytes: usize,
) -> Result<()> {
    check_private_directory_capacity(
        directory,
        additional_files,
        additional_bytes,
        max_files,
        max_bytes,
        "admission record",
        "admissions",
    )
}

/// Publish while holding the inventory writer lock, after the original signed
/// receipt and before worker admission. Repeated publication verifies the
/// existing object; immutable evidence is never overwritten or re-signed here.
#[cfg_attr(not(test), allow(dead_code))]
fn retain_admission_record(
    protected_root: &Path,
    admission: &NativeSessionAdmission,
) -> Result<()> {
    let root = load_runtime_evidence_product_root(
        &protected_root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH),
    )?;
    let key = root.verifying_key();
    drop(root);
    retain_admission_record_with_root(protected_root, admission, &key, None, false)
}

#[cfg_attr(not(test), allow(dead_code))]
fn retain_admission_record_with_root(
    protected_root: &Path,
    admission: &NativeSessionAdmission,
    verifying_key: &ed25519_dalek::VerifyingKey,
    pre_encoded_json: Option<&str>,
    receipt_already_verified: bool,
) -> Result<()> {
    use std::io::Write as _;

    if !receipt_already_verified {
        read_admission_receipt(protected_root, admission, verifying_key)?
            .context("native-session admission record requires its original signed receipt")?;
    }
    let owned_bytes;
    let bytes = match pre_encoded_json {
        Some(json) => json,
        None => {
            owned_bytes = bounded_json(admission, MAX_ADMISSION_BYTES)?;
            owned_bytes.as_str()
        }
    };
    let directory = protected_root.join(ADMISSION_RECORD_DIRECTORY);
    let created_directory = ensure_runtime_evidence_directory_with_status(&directory, true)?;
    let path = admission_record_path(protected_root, &admission.session_nonce);
    let exists = validate_private_path_if_present(&path)?;
    check_admission_record_capacity(
        &directory,
        usize::from(!exists),
        if exists { 0 } else { bytes.len() },
        MAX_STORED_SESSIONS,
        MAX_RETAINED_ADMISSION_BYTES,
    )?;
    let mut published_new = false;
    if !exists {
        let mut staged = tempfile::NamedTempFile::new_in(&directory)
            .context("stage private native-session admission record")?;
        staged.write_all(bytes.as_bytes())?;
        staged.as_file().sync_all()?;
        match staged.persist_noclobber(&path) {
            Ok(_) => published_new = true,
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error.error).context("publish native-session admission record");
            }
        }
    }
    if !published_new {
        let (retained, _) = read_retained_admission_record(
            protected_root,
            &admission.session_nonce,
            verifying_key,
        )?
        .context("retained native-session admission record disappeared during publication")?;
        if &retained != admission {
            bail!("retained native-session admission record conflicts with the admitted body");
        }
    }
    #[cfg(unix)]
    if published_new {
        std::fs::File::open(&directory)?.sync_all()?;
        if created_directory {
            std::fs::File::open(protected_root)?.sync_all()?;
        }
    }
    #[cfg(not(unix))]
    let _ = (created_directory, published_new);
    Ok(())
}

/// Stage and durably flush pre-spawn admission artifacts (optionally including
/// the freshly minted identity capture and pre-staged effect-journal header,
/// plus the unpublished supervisor ownership lease) in parallel before
/// publishing `identity-capture` -> `session-admission` -> `session-admission-record`
/// in strict causal order and coalescing their directory `fsync`s. The staged
/// supervisor lease remains unpublished until uniqueness/capacity checks pass
/// inside the `native-sessions.db` transaction, and the staged effect journal
/// remains unpublished until `native-sessions.db` commits with `admitted == true`,
/// so refused admissions leave neither artifact behind.
#[allow(clippy::too_many_arguments)]
fn retain_pre_spawn_artifacts_with_root(
    protected_root: &Path,
    admission: &NativeSessionAdmission,
    root: &ed25519_dalek::SigningKey,
    verifying_key: &ed25519_dalek::VerifyingKey,
    admission_json: &str,
    deferred_capture_bytes: Option<&[u8]>,
    stage_journal: bool,
) -> Result<(
    Option<super::native_session_journal::StagedNativeSessionEffectJournal>,
    supervisor_lease::StagedSupervisorLease,
    String,
)> {
    use std::io::Write as _;

    let capture_dir = protected_root.join(RUNTIME_EVIDENCE_CAPTURE_DIR_RELATIVE_PATH);
    let receipt_dir = protected_root.join(ADMISSION_RECEIPT_DIRECTORY);
    let record_dir = protected_root.join(ADMISSION_RECORD_DIRECTORY);
    let receipt_path = admission_receipt_path(protected_root, &admission.session_nonce);
    let record_path = admission_record_path(protected_root, &admission.session_nonce);

    // Sign the admission receipt first so both the staged effect journal and
    // staged supervisor lease bind to the exact `admission_sha256` inside the
    // same parallel flush barrier.
    let receipt =
        NativeSessionAdmissionReceipt::issue_with_verifying_key(admission, root, verifying_key)?;
    let receipt_bytes = bounded_json(&receipt, MAX_ADMISSION_RECEIPT_BYTES)?;
    let admission_sha256 = receipt.admission_sha256.clone();

    // Phase 1: Stage and `fsync` all pre-spawn temp files concurrently so ext4
    // jbd2 coalesces up to 5 file `fsync`s into one journal commit and overlaps
    // `check_admission_record_capacity` with disk flush. No final path is
    // published yet.
    let (capture_stage, receipt_stage, journal_stage, lease_stage, record_stage) =
        std::thread::scope(|scope| {
            let capture_handle = deferred_capture_bytes.map(|capture_bytes| {
                scope.spawn(|| -> Result<tempfile::NamedTempFile> {
                    let mut staged = tempfile::NamedTempFile::new_in(&capture_dir)
                        .context("stage private runtime evidence identity capture")?;
                    validate_runtime_evidence_private_file_metadata(
                        &admission.identity_capture_path,
                        &staged.as_file().metadata().with_context(|| {
                            format!(
                                "inspect staged runtime evidence capture {}",
                                admission.identity_capture_path.display()
                            )
                        })?,
                    )?;
                    staged.write_all(capture_bytes)?;
                    staged.as_file().sync_all()?;
                    Ok(staged)
                })
            });

            let receipt_handle = scope.spawn(|| -> Result<(tempfile::NamedTempFile, bool)> {
                let created_dir =
                    ensure_runtime_evidence_directory_with_status(&receipt_dir, true)?;
                let mut staged = tempfile::NamedTempFile::new_in(&receipt_dir)
                    .context("stage private native-session admission receipt")?;
                staged.write_all(receipt_bytes.as_bytes())?;
                staged.as_file().sync_all()?;
                Ok((staged, created_dir))
            });

            let journal_handle = if stage_journal {
                let root_clone = root.clone();
                let admission_sha256 = admission_sha256.as_str();
                Some(scope.spawn(move || {
                    super::native_session_journal::StagedNativeSessionEffectJournal::stage(
                        protected_root,
                        &admission.session_nonce,
                        &admission.product_root_key_id,
                        admission_sha256,
                        root_clone,
                    )
                }))
            } else {
                None
            };

            let lease_handle = {
                let admission_sha256 = admission_sha256.as_str();
                scope.spawn(move || {
                    supervisor_lease::stage(
                        protected_root,
                        &supervisor_lease::Binding {
                            session_nonce: &admission.session_nonce,
                            product_root_key_id: &admission.product_root_key_id,
                            admission_sha256,
                        },
                        root,
                    )
                })
            };

            let record_result = (|| -> Result<(Option<tempfile::NamedTempFile>, bool)> {
                let created_dir = ensure_runtime_evidence_directory_with_status(&record_dir, true)?;
                let exists = validate_private_path_if_present(&record_path)?;
                check_admission_record_capacity(
                    &record_dir,
                    usize::from(!exists),
                    if exists { 0 } else { admission_json.len() },
                    MAX_STORED_SESSIONS,
                    MAX_RETAINED_ADMISSION_BYTES,
                )?;
                let staged = if exists {
                    None
                } else {
                    let mut staged = tempfile::NamedTempFile::new_in(&record_dir)
                        .context("stage private native-session admission record")?;
                    staged.write_all(admission_json.as_bytes())?;
                    staged.as_file().sync_all()?;
                    Some(staged)
                };
                Ok((staged, created_dir))
            })();

            let capture_result = capture_handle.map(|handle| {
                handle.join().unwrap_or_else(|_| {
                    Err(anyhow::anyhow!("identity capture staging thread panicked"))
                })
            });
            let receipt_result = receipt_handle.join().unwrap_or_else(|_| {
                Err(anyhow::anyhow!("admission receipt staging thread panicked"))
            });
            let journal_result = journal_handle.map(|handle| {
                handle.join().unwrap_or_else(|_| {
                    Err(anyhow::anyhow!("effect journal staging thread panicked"))
                })
            });
            let lease_result = lease_handle.join().unwrap_or_else(|_| {
                Err(anyhow::anyhow!("supervisor lease staging thread panicked"))
            });
            (
                capture_result,
                receipt_result,
                journal_result,
                lease_result,
                record_result,
            )
        });

    let capture_staged = capture_stage.transpose()?;
    let (receipt_staged, created_receipt_dir) = receipt_stage?;
    let journal_staged = journal_stage.transpose()?;
    let lease_staged = lease_stage?;
    let (record_staged, created_record_dir) = record_stage?;

    // Phase 2: Publish in strict causal order:
    //   1. identity capture (when deferred)
    //   2. signed admission receipt
    //   3. canonical admission record
    // Preserves the invariant that neither receipt nor record ever exists
    // without its upstream identity/authority artifact.
    let mut published_capture = false;
    if let (Some(staged), Some(capture_bytes)) = (capture_staged, deferred_capture_bytes) {
        match staged.persist_noclobber(&admission.identity_capture_path) {
            Ok(_) => published_capture = true,
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = read_runtime_evidence_private_file(
                    &admission.identity_capture_path,
                    64 * 1024,
                )?;
                if !crate::security::constant_time::ct_eq_bytes(&existing, capture_bytes) {
                    bail!(
                        "runtime evidence identity capture {} already exists with different contents",
                        admission.identity_capture_path.display()
                    );
                }
            }
            Err(error) => {
                return Err(error.error).context("publish runtime evidence identity capture");
            }
        }
    }

    let mut published_receipt = false;
    match receipt_staged.persist_noclobber(&receipt_path) {
        Ok(_) => published_receipt = true,
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            read_admission_receipt(protected_root, admission, verifying_key)?
                .context("retained native-session admission disappeared during publication")?;
        }
        Err(error) => return Err(error.error).context("publish native-session admission receipt"),
    }

    let mut published_record = false;
    if let Some(staged) = record_staged {
        match staged.persist_noclobber(&record_path) {
            Ok(_) => published_record = true,
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error.error).context("publish native-session admission record");
            }
        }
    }
    if !published_record {
        let (retained, _) = read_retained_admission_record(
            protected_root,
            &admission.session_nonce,
            verifying_key,
        )?
        .context("retained native-session admission record disappeared during publication")?;
        if &retained != admission {
            bail!("retained native-session admission record conflicts with the admitted body");
        }
    }

    // Phase 3: Coalesce all published directory `fsync`s concurrently before DB
    // insertion.
    #[cfg(unix)]
    {
        let sync_protected_root =
            (published_receipt && created_receipt_dir) || (published_record && created_record_dir);
        let mut dirs_to_sync: Vec<&Path> = Vec::with_capacity(3);
        if published_capture {
            dirs_to_sync.push(capture_dir.as_path());
        }
        if published_receipt {
            dirs_to_sync.push(receipt_dir.as_path());
        }
        if published_record {
            dirs_to_sync.push(record_dir.as_path());
        }
        match dirs_to_sync.as_slice() {
            [] => {}
            [only] => {
                std::fs::File::open(only)?.sync_all()?;
            }
            [first, rest @ ..] => {
                let results =
                    std::thread::scope(|scope| {
                        let handles: Vec<_> = rest
                            .iter()
                            .copied()
                            .map(|dir| scope.spawn(move || std::fs::File::open(dir)?.sync_all()))
                            .collect();
                        let first_res = std::fs::File::open(first).and_then(|dir| dir.sync_all());
                        let mut all = Vec::with_capacity(handles.len() + 1);
                        all.push(first_res);
                        for handle in handles {
                            all.push(handle.join().unwrap_or_else(|_| {
                                Err(std::io::Error::other("dir sync panicked"))
                            }));
                        }
                        all
                    });
                for res in results {
                    res?;
                }
            }
        }
        if sync_protected_root {
            std::fs::File::open(protected_root)?.sync_all()?;
        }
    }
    #[cfg(not(unix))]
    let _ = (
        capture_dir,
        created_receipt_dir,
        created_record_dir,
        published_capture,
        published_receipt,
        published_record,
    );
    Ok((journal_staged, lease_staged, admission_sha256))
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

#[cfg_attr(not(test), allow(dead_code))]
fn retain_admission_receipt(
    protected_root: &Path,
    admission: &NativeSessionAdmission,
) -> Result<()> {
    let capture_directory = protected_root.join(RUNTIME_EVIDENCE_CAPTURE_DIR_RELATIVE_PATH);
    if admission.identity_capture_path.parent() != Some(capture_directory.as_path()) {
        bail!("native-session capture is outside its protected capture directory");
    }
    ensure_runtime_evidence_directory(&capture_directory, true)?;
    ensure_runtime_evidence_directory(&protected_root.join("keys"), true)?;
    let root = load_runtime_evidence_product_root(
        &protected_root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH),
    )?;
    let key = root.verifying_key();
    verify_admission_capture_with_root(protected_root, admission, &key)?;
    retain_admission_receipt_with_root(protected_root, admission, &root, &key)
}

#[cfg_attr(not(test), allow(dead_code))]
fn retain_admission_receipt_with_root(
    protected_root: &Path,
    admission: &NativeSessionAdmission,
    root: &ed25519_dalek::SigningKey,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<()> {
    use std::io::Write as _;

    let receipt =
        NativeSessionAdmissionReceipt::issue_with_verifying_key(admission, root, verifying_key)?;
    let bytes = bounded_json(&receipt, MAX_ADMISSION_RECEIPT_BYTES)?;
    let directory = protected_root.join(ADMISSION_RECEIPT_DIRECTORY);
    let created_directory = ensure_runtime_evidence_directory_with_status(&directory, true)?;
    let path = admission_receipt_path(protected_root, &admission.session_nonce);
    let mut staged = tempfile::NamedTempFile::new_in(&directory)
        .context("stage private native-session admission receipt")?;
    staged.write_all(bytes.as_bytes())?;
    staged.as_file().sync_all()?;
    let mut published_new = false;
    match staged.persist_noclobber(&path) {
        Ok(_) => published_new = true,
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            read_admission_receipt(protected_root, admission, verifying_key)?
                .context("retained native-session admission disappeared during publication")?;
        }
        Err(error) => return Err(error.error).context("publish native-session admission receipt"),
    }
    // A receipt with no committed inventory row never certifies that the
    // worker ran or stopped; its identity capture stays untracked/indeterminate.
    #[cfg(unix)]
    if published_new {
        std::fs::File::open(&directory)?.sync_all()?;
        if created_directory {
            std::fs::File::open(protected_root)?.sync_all()?;
        }
    }
    #[cfg(not(unix))]
    let _ = (created_directory, published_new);
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
    let capture_directory = protected_root.join(RUNTIME_EVIDENCE_CAPTURE_DIR_RELATIVE_PATH);
    let root = load_runtime_evidence_product_root(
        &protected_root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH),
    )?;
    let key = root.verifying_key();
    let mut ensured_capture_dirs = false;
    for record in records {
        if record.admission.identity_capture_path.parent() != Some(capture_directory.as_path()) {
            bail!("native-session capture is outside its protected capture directory");
        }
        if !ensured_capture_dirs {
            ensure_runtime_evidence_directory(&capture_directory, true)?;
            ensure_runtime_evidence_directory(&protected_root.join("keys"), true)?;
            ensured_capture_dirs = true;
        }
        verify_admission_capture_with_root(protected_root, &record.admission, &key)?;
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

#[cfg(unix)]
type PrivateFileIdentity = (u64, u64, u64, i64, i64, i64, i64);

#[cfg(unix)]
fn capture_private_file_identity(path: &Path, expected_uid: u32) -> Option<PrivateFileIdentity> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = std::fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || (metadata.permissions().mode() & 0o077) != 0
        || metadata.nlink() != 1
        || metadata.uid() != expected_uid
    {
        return None;
    }
    Some((
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    ))
}

#[cfg(unix)]
fn capture_private_dir_identity(path: &Path, expected_uid: u32) -> Option<(u64, u64, u32)> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = std::fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || (metadata.permissions().mode() & 0o077) != 0
        || metadata.uid() != expected_uid
    {
        return None;
    }
    Some((
        metadata.dev(),
        metadata.ino(),
        metadata.permissions().mode() & 0o777,
    ))
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct WalFileFingerprint {
    identity: PrivateFileIdentity,
    sha256: [u8; 32],
}

/// Content-and-metadata fingerprint of `native-sessions.db` and its WAL.
/// Used strictly as an in-memory acceleration proof between `admit` and
/// `finish` inside one supervisor process; any mismatch or missing proof falls
/// back to the full SQL aggregate query.
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct DatabaseStateFingerprint {
    db_identity: PrivateFileIdentity,
    db_header: Vec<u8>,
    wal: Option<WalFileFingerprint>,
}

#[cfg(unix)]
fn read_private_file_header(
    path: &Path,
    expected_uid: u32,
    head_len: usize,
) -> Option<(PrivateFileIdentity, Vec<u8>)> {
    use rustix::fs::{Mode, OFlags, open};
    use std::os::unix::fs::{FileExt as _, MetadataExt as _, PermissionsExt as _};

    let file = std::fs::File::from(
        open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .ok()?,
    );
    let meta = file.metadata().ok()?;
    if !meta.is_file()
        || (meta.permissions().mode() & 0o077) != 0
        || meta.nlink() != 1
        || meta.uid() != expected_uid
    {
        return None;
    }
    let file_len = meta.len();
    let head_count = usize::try_from(file_len.min(head_len as u64)).ok()?;
    let mut head = vec![0_u8; head_count];
    if head_count > 0 {
        file.read_exact_at(&mut head, 0).ok()?;
    }
    let after = file.metadata().ok()?;
    let identity = (
        meta.dev(),
        meta.ino(),
        file_len,
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec(),
    );
    let after_identity = (
        after.dev(),
        after.ino(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    );
    if identity != after_identity {
        return None;
    }
    Some((identity, head))
}

#[cfg(unix)]
fn hash_bounded_private_file(
    path: &Path,
    expected_uid: u32,
    max_len: u64,
) -> Option<WalFileFingerprint> {
    use rustix::fs::{Mode, OFlags, open};
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let mut file = std::fs::File::from(
        open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .ok()?,
    );
    let meta = file.metadata().ok()?;
    if !meta.is_file()
        || (meta.permissions().mode() & 0o077) != 0
        || meta.nlink() != 1
        || meta.uid() != expected_uid
        || meta.len() > max_len
    {
        return None;
    }
    let file_len = meta.len();
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buf = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buf).ok()?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64)?;
        if total > max_len {
            return None;
        }
        hasher.update(&buf[..read]);
    }
    if total != file_len {
        return None;
    }
    let after = file.metadata().ok()?;
    let identity = (
        meta.dev(),
        meta.ino(),
        file_len,
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec(),
    );
    let after_identity = (
        after.dev(),
        after.ino(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    );
    if identity != after_identity {
        return None;
    }
    Some(WalFileFingerprint {
        identity,
        sha256: hasher.finalize().into(),
    })
}

#[cfg(unix)]
fn database_state_fingerprint(protected_root: &Path) -> Option<DatabaseStateFingerprint> {
    const MAX_FINGERPRINTED_WAL_BYTES: u64 = 512 * 1024;

    let expected_uid = rustix::process::geteuid().as_raw();
    let journal_path = protected_root.join(format!("{INVENTORY_FILE}-journal"));
    match std::fs::symlink_metadata(&journal_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return None,
    }
    let db_path = protected_root.join(INVENTORY_FILE);
    let (db_identity, db_header) = read_private_file_header(&db_path, expected_uid, 100)?;
    let wal_path = protected_root.join(format!("{INVENTORY_FILE}-wal"));
    let wal = match std::fs::symlink_metadata(&wal_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Ok(_) => Some(hash_bounded_private_file(
            &wal_path,
            expected_uid,
            MAX_FINGERPRINTED_WAL_BYTES,
        )?),
        Err(_) => return None,
    };
    Some(DatabaseStateFingerprint {
        db_identity,
        db_header,
        wal,
    })
}

struct CachedOutcomeSigningContext {
    product_root: ed25519_dalek::SigningKey,
    verifying_key: ed25519_dalek::VerifyingKey,
    #[cfg(unix)]
    keys_dir_identity: Option<(u64, u64, u32)>,
    #[cfg(unix)]
    capture_dir_identity: Option<(u64, u64, u32)>,
    #[cfg(unix)]
    root_key_identity: Option<PrivateFileIdentity>,
    #[cfg(unix)]
    capture_identity: Option<PrivateFileIdentity>,
}

fn retain_outcome_receipt(
    protected_root: &Path,
    admission: &NativeSessionAdmission,
    outcome: &NativeSessionOutcome,
) -> Result<()> {
    retain_outcome_receipt_with_cached_root(protected_root, admission, outcome, None)
}

fn retain_outcome_receipt_with_cached_root(
    protected_root: &Path,
    admission: &NativeSessionAdmission,
    outcome: &NativeSessionOutcome,
    cached_root: Option<&CachedOutcomeSigningContext>,
) -> Result<()> {
    use std::io::Write as _;

    let capture_directory = protected_root.join(RUNTIME_EVIDENCE_CAPTURE_DIR_RELATIVE_PATH);
    if admission.identity_capture_path.parent() != Some(capture_directory.as_path()) {
        bail!("native-session capture is outside its protected capture directory");
    }
    let keys_directory = protected_root.join("keys");
    let root_key_path = protected_root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH);
    #[cfg(unix)]
    let fast_root = cached_root.and_then(|cached| {
        let expected_keys_dir = cached.keys_dir_identity?;
        let expected_capture_dir = cached.capture_dir_identity?;
        let expected_key = cached.root_key_identity?;
        let expected_capture = cached.capture_identity?;
        let expected_uid = rustix::process::geteuid().as_raw();
        let current_keys_dir = capture_private_dir_identity(&keys_directory, expected_uid)?;
        let current_capture_dir = capture_private_dir_identity(&capture_directory, expected_uid)?;
        let current_key = capture_private_file_identity(&root_key_path, expected_uid)?;
        let current_capture =
            capture_private_file_identity(&admission.identity_capture_path, expected_uid)?;
        if current_keys_dir == expected_keys_dir
            && current_capture_dir == expected_capture_dir
            && current_key == expected_key
            && current_capture == expected_capture
        {
            Some((&cached.product_root, &cached.verifying_key))
        } else {
            None
        }
    });
    #[cfg(not(unix))]
    let fast_root: Option<(&ed25519_dalek::SigningKey, &ed25519_dalek::VerifyingKey)> = {
        let _ = cached_root;
        None
    };

    let loaded_root;
    let loaded_key;
    let (root, key) = if let Some((root_ref, key_ref)) = fast_root {
        (root_ref, key_ref)
    } else {
        ensure_runtime_evidence_directory(&capture_directory, true)?;
        ensure_runtime_evidence_directory(&keys_directory, true)?;
        loaded_root = load_runtime_evidence_product_root(&root_key_path)?;
        loaded_key = loaded_root.verifying_key();
        verify_admission_capture_with_root(protected_root, admission, &loaded_key)?;
        (&loaded_root, &loaded_key)
    };
    let receipt =
        NativeSessionOutcomeReceipt::issue_with_verifying_key(admission, outcome, root, key)?;
    let bytes = bounded_json(&receipt, MAX_OUTCOME_RECEIPT_BYTES)?;
    let directory = protected_root.join(OUTCOME_RECEIPT_DIRECTORY);
    let created_directory = ensure_runtime_evidence_directory_with_status(&directory, true)?;
    let path = outcome_receipt_path(protected_root, &admission.session_nonce);
    let mut staged = tempfile::NamedTempFile::new_in(&directory)
        .context("stage private native-session outcome receipt")?;
    staged.write_all(bytes.as_bytes())?;
    staged.as_file().sync_all()?;
    let mut published_new = false;
    match staged.persist_noclobber(&path) {
        Ok(_) => published_new = true,
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = read_outcome_receipt(protected_root, admission, key)?
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
    if published_new {
        std::fs::File::open(&directory)?.sync_all()?;
        if created_directory {
            std::fs::File::open(protected_root)?.sync_all()?;
        }
    }
    #[cfg(not(unix))]
    let _ = (created_directory, published_new);
    Ok(())
}

/// Fast O(1) outcome persistence used when `DatabaseStateFingerprint` proves
/// zero external writes occurred to `native-sessions.db` or its WAL since this
/// supervisor process committed the session admission.
#[cfg(unix)]
fn write_observed_outcome_with_verified_usage(
    tx: &mut Transaction<'_>,
    expected_admission: &NativeSessionAdmission,
    outcome: &NativeSessionOutcome,
    count: usize,
    bytes: usize,
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
    let [admission_val, existing] = row.values() else {
        bail!("native-session outcome row shape is invalid");
    };
    let admission: NativeSessionAdmission = parse_json(admission_val, MAX_ADMISSION_BYTES)?;
    validate_admission(&admission)?;
    if admission != *expected_admission {
        bail!("native-session admission changed before outcome persistence");
    }
    validate_outcome(&admission, outcome)?;
    let json = bounded_json(outcome, MAX_OUTCOME_BYTES)?;
    let post_bytes = match existing {
        SqliteValue::Null => {
            let outcome_len = json.len();
            tx.execute_with_params(
                "UPDATE native_sessions SET outcome_json = ?1
                 WHERE session_nonce = ?2 AND outcome_json IS NULL;",
                &[
                    SqliteValue::Text(json.into()),
                    SqliteValue::Text(admission.session_nonce.into()),
                ],
            )?;
            bytes
                .checked_sub(MAX_OUTCOME_BYTES)
                .and_then(|base| base.checked_add(outcome_len))
                .context("native-session reservation accounting overflowed")?
        }
        value => {
            let existing: NativeSessionOutcome = parse_json(value, MAX_OUTCOME_BYTES)?;
            if existing != *outcome {
                bail!("native-session outcome is immutable once observed");
            }
            bytes
        }
    };
    check_reservation_usage(count, post_bytes, MAX_STORED_SESSIONS, MAX_RESERVED_BYTES)
}

/// Combined single-query outcome persistence and reservation bounds check for
/// `persist_outcome`. Fetches the target admission/outcome alongside the exact
/// table count and reserved-byte sum in one SQLite round-trip, updates the row
/// if still pending, and checks the exact post-update reservation usage.
fn write_observed_outcome_and_check_bounds(
    tx: &mut Transaction<'_>,
    expected_admission: &NativeSessionAdmission,
    outcome: &NativeSessionOutcome,
) -> Result<()> {
    let rows = tx.query_with_params(
        &format!(
            "SELECT
                 (SELECT admission_json FROM native_sessions WHERE session_nonce = ?1),
                 (SELECT outcome_json FROM native_sessions WHERE session_nonce = ?1),
                 COUNT(*),
                 COALESCE(SUM(LENGTH(CAST(admission_json AS BLOB)) + CASE
                     WHEN outcome_json IS NULL THEN {MAX_OUTCOME_BYTES}
                     ELSE LENGTH(CAST(outcome_json AS BLOB)) END), 0)
             FROM native_sessions;"
        ),
        &[SqliteValue::Text(
            expected_admission.session_nonce.clone().into(),
        )],
    )?;
    let [row] = rows.as_slice() else {
        bail!("native-session outcome row shape is invalid");
    };
    let [
        admission_val,
        existing,
        SqliteValue::Integer(count),
        SqliteValue::Integer(bytes),
    ] = row.values()
    else {
        bail!("native-session outcome row shape is invalid");
    };
    if matches!(admission_val, SqliteValue::Null) {
        bail!("native-session admission disappeared before outcome persistence");
    }
    let admission: NativeSessionAdmission = parse_json(admission_val, MAX_ADMISSION_BYTES)?;
    validate_admission(&admission)?;
    if admission != *expected_admission {
        bail!("native-session admission changed before outcome persistence");
    }
    validate_outcome(&admission, outcome)?;
    let json = bounded_json(outcome, MAX_OUTCOME_BYTES)?;
    let count = usize::try_from(*count)?;
    let bytes = usize::try_from(*bytes)?;
    let post_bytes = match existing {
        SqliteValue::Null => {
            let outcome_len = json.len();
            tx.execute_with_params(
                "UPDATE native_sessions SET outcome_json = ?1
                 WHERE session_nonce = ?2 AND outcome_json IS NULL;",
                &[
                    SqliteValue::Text(json.into()),
                    SqliteValue::Text(admission.session_nonce.into()),
                ],
            )?;
            bytes
                .checked_sub(MAX_OUTCOME_BYTES)
                .and_then(|base| base.checked_add(outcome_len))
                .context("native-session reservation accounting overflowed")?
        }
        value => {
            let existing: NativeSessionOutcome = parse_json(value, MAX_OUTCOME_BYTES)?;
            if existing != *outcome {
                bail!("native-session outcome is immutable once observed");
            }
            bytes
        }
    };
    check_reservation_usage(count, post_bytes, MAX_STORED_SESSIONS, MAX_RESERVED_BYTES)
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

/// Authenticate the complete recovery batch before changing any projections.
/// Receipt absence is not an outcome and cannot release a pending reservation.
fn retained_outcome_recoveries<'a>(
    protected_root: &Path,
    records: &'a [NativeSessionInventoryRecord],
) -> Result<Vec<(&'a NativeSessionAdmission, NativeSessionOutcome)>> {
    if records.iter().all(|record| record.outcome.is_some()) {
        return Ok(Vec::new());
    }
    let directory = protected_root.join(OUTCOME_RECEIPT_DIRECTORY);
    match std::fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).context("inspect retained native-session outcomes"),
        Ok(_) => ensure_runtime_evidence_directory(&directory, true)?,
    }
    let capture_directory = protected_root.join(RUNTIME_EVIDENCE_CAPTURE_DIR_RELATIVE_PATH);
    let root = load_runtime_evidence_product_root(
        &protected_root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH),
    )?;
    let key = root.verifying_key();
    let mut ensured_capture_dirs = false;
    let mut recoveries = Vec::new();
    let mut recovered_bytes = 0_usize;
    for record in records.iter().filter(|record| record.outcome.is_none()) {
        if let Some(receipt) = read_outcome_receipt(protected_root, &record.admission, &key)? {
            if record.admission.identity_capture_path.parent() != Some(capture_directory.as_path())
            {
                bail!("native-session capture is outside its protected capture directory");
            }
            if !ensured_capture_dirs {
                ensure_runtime_evidence_directory(&capture_directory, true)?;
                ensure_runtime_evidence_directory(&protected_root.join("keys"), true)?;
                ensured_capture_dirs = true;
            }
            verify_admission_capture_with_root(protected_root, &record.admission, &key)?;
            recovered_bytes = recovered_bytes
                .checked_add(bounded_json(&receipt.outcome, MAX_OUTCOME_BYTES)?.len())
                .context("native-session recovery byte accounting overflowed")?;
            if recovered_bytes > MAX_RESERVED_BYTES {
                bail!("native-session signed recovery outcomes exceed the aggregate byte bound");
            }
            recoveries.push((&record.admission, receipt.outcome));
        }
    }
    Ok(recoveries)
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
    let recoveries = retained_outcome_recoveries(protected_root, records)?;
    if recoveries.is_empty() {
        return Ok(());
    }
    let _write_lock = lock_inventory_file(protected_root, false)?;
    retry_snapshot_conflict(|| {
        let fresh = open_inventory_unlocked(protected_root, false)?;
        let active_conn = fresh.as_ref().unwrap_or(connection);
        let mut tx = active_conn.transaction()?;
        for (admission, outcome) in &recoveries {
            write_observed_outcome(&mut tx, admission, outcome)?;
        }
        check_bounds(&tx)?;
        tx.commit()?;
        protect_sidecars(protected_root)?;
        Ok(())
    })?;
    tracing::info!(
        event_code = "NATIVE_SESSION_OUTCOMES_RECOVERED",
        recovered_sessions = recoveries.len(),
        "recovered authenticated supervisor observations; unresolved effects retain their original status"
    );
    Ok(())
}

/// Reclaim only reservations backed by already signed observations, within
/// the caller's admission transaction and inventory lock. Bound the temporary
/// read by the existing budget plus the newly inserted row's exact reservation;
/// the original budget is checked again before commit. Successful ordinary
/// admission does not scan historical receipts or repeat its aggregate query.
/// Genuine missing outcomes retain their complete reserved space.
fn recover_admission_capacity(
    protected_root: &Path,
    tx: &mut Transaction<'_>,
    new_session_nonce: &str,
    additional_bytes: usize,
) -> Result<usize> {
    check_bounds_with_limits(
        tx,
        MAX_STORED_SESSIONS,
        MAX_RESERVED_BYTES.saturating_add(additional_bytes),
    )?;
    let mut records = read_records_in_transaction_matching(tx, true)?;
    // A retained receipt for a retried identity cannot finalize the worker
    // this admission is about to start or release its new reservation.
    records.retain(|record| record.admission.session_nonce != new_session_nonce);
    let recoveries = retained_outcome_recoveries(protected_root, &records)?;
    for (admission, outcome) in &recoveries {
        write_observed_outcome(tx, admission, outcome)?;
    }
    Ok(recoveries.len())
}

/// An owned supervisor obligation. Dropping this on an ordinary error records
/// only the observations already made. Process death bypasses Drop and leaves
/// the durable admission pending unless an exact signed outcome was already
/// retained. Neither missing process liveness nor elapsed time can resolve it.
pub(crate) struct NativeSessionInventoryGuard {
    connection: Connection,
    database_identity: Option<(u64, u64)>,
    protected_root: PathBuf,
    admission: NativeSessionAdmission,
    session_nonce: String,
    process: NativeSessionProcessObservation,
    containment_empty_observed: bool,
    finished: bool,
    supervisor_lease: Option<supervisor_lease::SupervisorLease>,
    cached_root: Option<CachedOutcomeSigningContext>,
    #[cfg(unix)]
    post_admit_usage: Option<(DatabaseStateFingerprint, usize, usize)>,
}

/// Deferred completion handle for an already-reaped native session. The CLI
/// retains its supervisor lease until project receipt, ledger, and incident
/// consumers finish using the hot identity and admission evidence. Only then
/// may finalization make the session eligible for compaction. Dropping this
/// handle without calling [`Self::finalize`] still persists the exact completed
/// observation synchronously on ordinary error and panic paths.
#[must_use = "finalize or drop the deferred native-session finalizer to persist the outcome"]
pub struct DeferredNativeSessionFinalizer {
    guard: NativeSessionInventoryGuard,
    kind: NativeSessionOutcomeKind,
    effects: NativeSessionEffectObservation,
}

impl DeferredNativeSessionFinalizer {
    pub(crate) fn new(
        guard: NativeSessionInventoryGuard,
        kind: NativeSessionOutcomeKind,
        effects: NativeSessionEffectObservation,
    ) -> Self {
        Self {
            guard,
            kind,
            effects,
        }
    }

    pub fn finalize(mut self) {
        self.guard.finish(self.kind, self.effects.clone());
    }
}

impl Drop for DeferredNativeSessionFinalizer {
    fn drop(&mut self) {
        self.guard.finish(self.kind, self.effects.clone());
    }
}

pub(crate) struct NativeSessionAdmissionTicket {
    generation: u64,
    protected_root: Option<PathBuf>,
    database_identity: Option<(u64, u64)>,
    connection: Option<Connection>,
    schema_verified: bool,
}

impl NativeSessionAdmissionTicket {
    fn bare(generation: u64) -> Self {
        Self {
            generation,
            protected_root: None,
            database_identity: None,
            connection: None,
            schema_verified: false,
        }
    }

    fn take_reusable_connection(
        &mut self,
        protected_root: &Path,
        database_identity: Option<(u64, u64)>,
    ) -> Option<(Connection, bool)> {
        if database_identity.is_none()
            || self.database_identity != database_identity
            || self.protected_root.as_deref() != Some(protected_root)
        {
            return None;
        }
        self.connection
            .take()
            .map(|connection| (connection, self.schema_verified))
    }
}

impl NativeSessionInventoryGuard {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn admit(
        protected_root: &Path,
        admission: NativeSessionAdmission,
        expected_generation: u64,
    ) -> Result<Self> {
        Self::admit_with_context(
            protected_root,
            admission,
            NativeSessionAdmissionTicket::bare(expected_generation),
            None,
        )
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn admit_with_context(
        protected_root: &Path,
        admission: NativeSessionAdmission,
        ticket: NativeSessionAdmissionTicket,
        preloaded_root: Option<(ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey)>,
    ) -> Result<Self> {
        let (guard, _) = Self::admit_with_context_inner(
            protected_root,
            admission,
            ticket,
            preloaded_root,
            None,
            None,
        )?;
        Ok(guard)
    }

    /// Admit a native session and publish its durable effect journal in one
    /// coalesced pre-spawn barrier: stages and `fsync`s `identity-captures`,
    /// `session-admissions`, `session-admission-records`, and the unpublished
    /// `session-effect-journals` header in parallel, promotes in strict causal
    /// order, commits `native-sessions.db`, and publishes the journal only once
    /// admission commits.
    pub(crate) fn admit_and_prepare_journal_with_capture(
        protected_root: &Path,
        admission: NativeSessionAdmission,
        ticket: NativeSessionAdmissionTicket,
        preloaded_root: (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey),
        capture: &RuntimeEvidenceIdentityCapture,
        capture_bytes: &[u8],
        retained_source_capsule: Option<&RetainedNativeSessionSourceCapsule>,
    ) -> Result<(
        Self,
        super::native_session_journal::NativeSessionEffectJournalWriter,
    )> {
        let (guard, journal) = Self::admit_with_context_inner(
            protected_root,
            admission,
            ticket,
            Some(preloaded_root),
            Some((capture, capture_bytes)),
            retained_source_capsule,
        )?;
        let journal =
            journal.context("native-session durable effect journal was not established")?;
        Ok((guard, journal))
    }

    fn admit_with_context_inner(
        protected_root: &Path,
        admission: NativeSessionAdmission,
        mut ticket: NativeSessionAdmissionTicket,
        preloaded_root: Option<(ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey)>,
        deferred_capture: Option<(&RuntimeEvidenceIdentityCapture, &[u8])>,
        retained_source_capsule: Option<&RetainedNativeSessionSourceCapsule>,
    ) -> Result<(
        Self,
        Option<super::native_session_journal::NativeSessionEffectJournalWriter>,
    )> {
        let expected_generation = ticket.generation;
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
        let serialization_scopes: BTreeSet<_> = expected_scopes
            .keys()
            .flat_map(|project| project.ancestors())
            .collect();
        let capture_directory = protected_root.join(RUNTIME_EVIDENCE_CAPTURE_DIR_RELATIVE_PATH);
        if admission.identity_capture_path.parent() != Some(capture_directory.as_path()) {
            bail!("native-session capture is outside its protected capture directory");
        }
        ensure_runtime_evidence_directory(&capture_directory, true)?;
        ensure_runtime_evidence_directory(&protected_root.join("keys"), true)?;
        let (product_root, verifying_key) = match preloaded_root {
            Some(pair) => pair,
            None => {
                let root = load_runtime_evidence_product_root(
                    &protected_root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH),
                )?;
                let key = root.verifying_key();
                (root, key)
            }
        };
        if let Some((capture, capture_bytes)) = deferred_capture {
            if capture_bytes.len() > 64 * 1024 {
                bail!("runtime evidence identity capture exceeds the 65536-byte bound");
            }
            capture.verify_with_product_root(&verifying_key)?;
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
        } else {
            verify_admission_capture_with_root(protected_root, &admission, &verifying_key)?;
        }
        let source_capsule_verified = retained_source_capsule
            .is_some_and(|proof| proof.verify_on_disk(protected_root, &admission));
        if !source_capsule_verified {
            read_retained_native_session_source_capsule(protected_root, &admission)
                .context("native-session sources must be retained before admission")?;
        }
        let admission_json = bounded_json(&admission, MAX_ADMISSION_BYTES)?;
        let write_lock = lock_inventory_file(protected_root, true)?;
        let database_identity = lock_file_identity(write_lock.as_ref());
        let mut connection = Some(
            match ticket.take_reusable_connection(protected_root, database_identity) {
                Some((connection, schema_verified)) => {
                    if !schema_verified {
                        retry_snapshot_conflict(|| ensure_inventory_schema(&connection))?;
                    }
                    connection
                }
                None => retry_snapshot_conflict(|| open_inventory_unlocked(protected_root, true))?
                    .context("native-session inventory was not created")?,
            },
        );
        let (mut staged_journal, staged_lease, admission_sha256) =
            retain_pre_spawn_artifacts_with_root(
                protected_root,
                &admission,
                &product_root,
                &verifying_key,
                &admission_json,
                deferred_capture.map(|(_, bytes)| bytes),
                deferred_capture.is_some(),
            )?;
        let mut staged_lease = Some(staged_lease);
        // Keep acquired descriptors across transaction retries. Refused
        // uniqueness/capacity checks must not create extra ownership objects.
        let mut supervisor_lease = None;
        let mut published_journal = None;
        // A refused attempt keeps the same decision and timestamp through
        // transaction retries. Its receipt is issued only after this unique
        // insertion commits, so a duplicate/losing admission cannot create a
        // false never-spawned receipt for an already running worker.
        let mut refused_outcome = None;
        let mut commit_attempt = 0_u32;
        let (admitted, recovered_sessions, committed_usage) = retry_snapshot_conflict(|| {
            if commit_attempt > 0 {
                connection = None;
                connection = Some(
                    open_inventory_unlocked(protected_root, true)?
                        .context("native-session inventory was not created")?,
                );
            }
            commit_attempt = commit_attempt.saturating_add(1);
            let active_connection = connection
                .as_ref()
                .context("native-session inventory connection missing")?;
            let mut tx = active_connection.transaction()?;
            // Every enclosing owner participates in the same conflict point.
            // Deduplicate shared ancestors of the release and operator roots;
            // a parent cannot seal a census concurrently with child admission.
            serialize_project_admissions(&mut tx, &serialization_scopes)?;
            let drains_has_rows = drains_table_has_rows_unchecked(&tx)?;
            let mut admitted = refused_outcome.is_none();
            for (project, expected_generation) in &expected_scopes {
                let (generation, held_fence) =
                    admission_scope_state_with_drains(&tx, project, drains_has_rows)?;
                admitted &= held_fence.is_none() && generation == Some(*expected_generation);
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
                    panic_evidence: None,
                });
                SqliteValue::Text(bounded_json(refused, MAX_OUTCOME_BYTES)?.into())
            };
            let outcome_bytes = match &outcome {
                SqliteValue::Text(json) => json.len(),
                _ => MAX_OUTCOME_BYTES,
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
            let (count, bytes) = inventory_reservation_usage(&tx)?;
            let recovered_sessions = if count <= MAX_STORED_SESSIONS && bytes > MAX_RESERVED_BYTES {
                recover_admission_capacity(
                    protected_root,
                    &mut tx,
                    &admission.session_nonce,
                    admission_json.len().saturating_add(outcome_bytes),
                )?
            } else {
                0
            };
            if recovered_sessions > 0 {
                check_bounds(&tx)?;
            } else {
                check_reservation_usage(count, bytes, MAX_STORED_SESSIONS, MAX_RESERVED_BYTES)?;
            }
            // The row is still private to this transaction and the inventory
            // writer lock excludes compaction and concurrent drain transitions.
            // Publish the pre-staged, locked, already-`fsync`ed ownership lease
            // (and, when `admitted`, the pre-staged effect journal) concurrently
            // so their two disjoint directory `fsync`s coalesce into one ext4
            // jbd2 barrier before `tx.commit()`. Refused/drain-fenced attempts
            // leave `staged_journal` unpublished so it drops cleanly below.
            let pending_lease = if supervisor_lease.is_none() {
                Some(staged_lease.take())
            } else {
                None
            };
            let pending_journal = if admitted && published_journal.is_none() {
                staged_journal.take()
            } else {
                None
            };
            match (pending_lease, pending_journal) {
                (Some(lease_opt), Some(journal_staged)) => {
                    let (lease_res, journal_res) = std::thread::scope(|scope| {
                        let journal_handle =
                            scope.spawn(|| journal_staged.publish(protected_root));
                        let lease_res = match lease_opt {
                            Some(staged) => staged.publish(protected_root),
                            None => supervisor_lease::acquire(
                                protected_root,
                                &supervisor_lease::Binding {
                                    session_nonce: &admission.session_nonce,
                                    product_root_key_id: &admission.product_root_key_id,
                                    admission_sha256: &admission_sha256,
                                },
                                &product_root,
                            ),
                        };
                        let journal_res = journal_handle.join().unwrap_or_else(|_| {
                            Err(anyhow::anyhow!("effect journal publication thread panicked"))
                        });
                        (lease_res, journal_res)
                    });
                    supervisor_lease = lease_res?;
                    published_journal = Some(journal_res.context(
                        "native-session durable effect journal could not be established; worker was not started",
                    )?);
                }
                (Some(lease_opt), None) => {
                    supervisor_lease = match lease_opt {
                        Some(staged) => staged.publish(protected_root)?,
                        None => supervisor_lease::acquire(
                            protected_root,
                            &supervisor_lease::Binding {
                                session_nonce: &admission.session_nonce,
                                product_root_key_id: &admission.product_root_key_id,
                                admission_sha256: &admission_sha256,
                            },
                            &product_root,
                        )?,
                    };
                }
                (None, Some(journal_staged)) => {
                    published_journal = Some(journal_staged.publish(protected_root).context(
                        "native-session durable effect journal could not be established; worker was not started",
                    )?);
                }
                (None, None) => {}
            }
            tx.commit()?;
            protect_sidecars(protected_root)?;
            let committed_usage = (recovered_sessions == 0 && admitted).then_some((count, bytes));
            Ok((admitted, recovered_sessions, committed_usage))
        })
        .context("persist native-session admission before worker spawn")?;
        #[cfg(unix)]
        let post_admit_usage = committed_usage.and_then(|(count, bytes)| {
            database_state_fingerprint(protected_root).map(|fp| (fp, count, bytes))
        });
        #[cfg(not(unix))]
        let _ = committed_usage;
        drop(write_lock);
        if recovered_sessions > 0 {
            tracing::info!(
                event_code = "NATIVE_SESSION_OUTCOMES_RECOVERED",
                recovered_sessions,
                "recovered authenticated supervisor observations during admission; unresolved effects retain their original status"
            );
        }
        if !admitted {
            drop(product_root);
            // Drop any staged journal temp file before recording the refused
            // outcome so a drain-fenced attempt leaves no journal artifact.
            drop(staged_journal);
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
        #[cfg(unix)]
        let (keys_dir_identity, capture_dir_identity, root_key_identity, capture_identity) = {
            let expected_uid = rustix::process::geteuid().as_raw();
            (
                capture_private_dir_identity(&protected_root.join("keys"), expected_uid),
                capture_private_dir_identity(
                    &protected_root.join(RUNTIME_EVIDENCE_CAPTURE_DIR_RELATIVE_PATH),
                    expected_uid,
                ),
                capture_private_file_identity(
                    &protected_root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH),
                    expected_uid,
                ),
                capture_private_file_identity(&admission.identity_capture_path, expected_uid),
            )
        };
        let guard = Self {
            connection: connection.context("native-session inventory connection missing")?,
            database_identity,
            protected_root: protected_root.to_path_buf(),
            session_nonce: admission.session_nonce.clone(),
            admission,
            process: NativeSessionProcessObservation::NotSpawned,
            containment_empty_observed: false,
            finished: false,
            supervisor_lease,
            cached_root: Some(CachedOutcomeSigningContext {
                product_root,
                verifying_key,
                #[cfg(unix)]
                keys_dir_identity,
                #[cfg(unix)]
                capture_dir_identity,
                #[cfg(unix)]
                root_key_identity,
                #[cfg(unix)]
                capture_identity,
            }),
            #[cfg(unix)]
            post_admit_usage,
        };
        let journal = match published_journal {
            Some(writer) => Some(writer),
            None => staged_journal
                .map(|staged| staged.publish(protected_root))
                .transpose()
                .context("native-session durable effect journal could not be established; worker was not started")?,
        };
        Ok((guard, journal))
    }

    /// Establish a durable provider journal before the worker can start. This
    /// uses the already retained admission and existing product root; neither
    /// a worker request nor a journal file can provision signing authority.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn prepare_effect_journal(
        &self,
    ) -> Result<super::native_session_journal::NativeSessionEffectJournalWriter> {
        if self.finished || self.process != NativeSessionProcessObservation::NotSpawned {
            bail!("native-session effect journal must be prepared before worker spawn");
        }
        validate_admission(&self.admission)?;
        let root = load_runtime_evidence_product_root(
            &self
                .protected_root
                .join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH),
        )?;
        let key = root.verifying_key();
        verify_admission_capture_with_root(&self.protected_root, &self.admission, &key)?;
        let receipt = read_admission_receipt(&self.protected_root, &self.admission, &key)?
            .context("native-session effect journal requires an authenticated admission")?;
        super::native_session_journal::NativeSessionEffectJournalWriter::create(
            &self.protected_root,
            &self.admission.session_nonce,
            &self.admission.product_root_key_id,
            &receipt.admission_sha256,
            root,
        )
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
            panic_evidence: None,
        };
        if let Err(error) = self.persist_outcome(&outcome) {
            // Preserve execution error/panic/success. The durable admission
            // remains pending and cannot falsely clear the missing outcome.
            tracing::warn!(session_nonce = %self.session_nonce, %error,
                "native-session outcome could not be persisted; admission remains unresolved");
        }
        self.finished = true;
        self.cached_root = None;
        #[cfg(unix)]
        {
            self.post_admit_usage = None;
        }
        // Reaping the worker alone is insufficient: deferred finalization keeps
        // ownership until the exact outcome persistence attempt has finished.
        self.supervisor_lease = None;
    }

    /// Retain details from an already validated Panicked response without
    /// changing its independently established effect classification. Optional
    /// detail must never displace the mandatory signed terminal observation.
    pub(crate) fn finish_panicked(
        &mut self,
        effects: NativeSessionEffectObservation,
        evidence: NativeSessionPanicEvidence,
    ) -> Result<()> {
        if self.finished {
            bail!("native-session panic outcome was already finalized");
        }
        let mut outcome = NativeSessionOutcome {
            observed_at: Utc::now(),
            kind: NativeSessionOutcomeKind::Panicked,
            process: self.process,
            containment_empty_observed: self.containment_empty_observed,
            effects,
            panic_evidence: Some(evidence),
        };
        let detail_error = validate_outcome(&self.admission, &outcome)
            .and_then(|()| bounded_json(&outcome, MAX_OUTCOME_BYTES).map(|_| ()))
            .err();
        if detail_error.is_some() {
            // Preserve the original caller's validated classification, not a
            // classification inferred from rejected or truncated WAL entries.
            // The caller must surface the error; no partial WAL is signed.
            outcome.panic_evidence = None;
        }
        let persisted = self.persist_outcome(&outcome);
        self.finished = true;
        self.cached_root = None;
        #[cfg(unix)]
        {
            self.post_admit_usage = None;
        }
        self.supervisor_lease = None;
        persisted.context("failed persisting the authenticated native panic outcome")?;
        if let Some(error) = detail_error {
            return Err(error.context(
                "native panic forensic detail was not retained; the original signed outcome classification was preserved",
            ));
        }
        Ok(())
    }

    fn persist_outcome(&self, outcome: &NativeSessionOutcome) -> Result<()> {
        retain_outcome_receipt_with_cached_root(
            &self.protected_root,
            &self.admission,
            outcome,
            self.cached_root.as_ref(),
        )?;
        let write_lock = lock_inventory_file(&self.protected_root, false)?;
        let reuse_connection = self.database_identity.is_some()
            && lock_file_identity(write_lock.as_ref()) == self.database_identity;
        #[cfg(unix)]
        let verified_usage = if reuse_connection {
            self.post_admit_usage
                .as_ref()
                .and_then(|(fp, count, bytes)| {
                    let current = database_state_fingerprint(&self.protected_root)?;
                    (current == *fp).then_some((*count, *bytes))
                })
        } else {
            None
        };
        let mut attempt = 0_u32;
        retry_snapshot_conflict(|| {
            let fresh = if attempt == 0 && reuse_connection {
                None
            } else {
                open_inventory_unlocked(&self.protected_root, false)?
            };
            let current_attempt = attempt;
            attempt = attempt.saturating_add(1);
            let active_conn = fresh.as_ref().unwrap_or(&self.connection);
            let mut tx = active_conn.transaction()?;
            #[cfg(unix)]
            if let Some((count, bytes)) = verified_usage.filter(|_| current_attempt == 0) {
                write_observed_outcome_with_verified_usage(
                    &mut tx,
                    &self.admission,
                    outcome,
                    count,
                    bytes,
                )?;
            } else {
                write_observed_outcome_and_check_bounds(&mut tx, &self.admission, outcome)?;
            }
            #[cfg(not(unix))]
            {
                let _ = current_attempt;
                write_observed_outcome_and_check_bounds(&mut tx, &self.admission, outcome)?;
            }
            tx.commit()?;
            drop(tx);
            // Keep the WAL bounded so subsequent opens do not replay hundreds
            // of frames on every `franken-node run`. `TRUNCATE` folds and
            // resets the WAL to 0 bytes when idle (preventing re-triggering on
            // every subsequent run), and returns `busy=1` non-blockingly under
            // fsqlite if another connection holds an active transaction.
            const WAL_CHECKPOINT_THRESHOLD_BYTES: u64 = 256 * 1024;
            let wal_path = self.protected_root.join(format!("{INVENTORY_FILE}-wal"));
            if std::fs::symlink_metadata(&wal_path)
                .is_ok_and(|meta| meta.is_file() && meta.len() >= WAL_CHECKPOINT_THRESHOLD_BYTES)
            {
                let _ = active_conn.query("PRAGMA wal_checkpoint(TRUNCATE);");
            }
            protect_sidecars(&self.protected_root)?;
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
    read_records_in_transaction_matching(tx, false)
}

/// The caller must bound the inventory within this transaction before loading
/// rows; admission recovery may temporarily include its uncommitted new row.
fn read_records_in_transaction_matching(
    tx: &Transaction<'_>,
    pending_only: bool,
) -> Result<Vec<NativeSessionInventoryRecord>> {
    let filter = if pending_only {
        "WHERE outcome_json IS NULL"
    } else {
        ""
    };
    let rows = tx.query(&format!(
        "SELECT session_nonce, admission_json, outcome_json FROM native_sessions
         {filter}
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
        || project_root.components().collect::<PathBuf>().as_os_str() != project_root.as_os_str()
    {
        // Component-wise scope membership must use the same spelling as the
        // SQL conflict key. Do not let aliases split one owner's admission lock.
        // This is lexical only: retained projects need not still exist on disk.
        bail!(
            "native-session drain requires a canonical absolute project identity without traversal"
        );
    }
    let key = project_root
        .to_str()
        .context("native-session drain project must be UTF-8")?;
    if key.len() > 4096 || key.as_bytes().contains(&0) || project_root.components().count() > 128 {
        bail!("native-session drain project identity exceeds its bounded control scope");
    }
    Ok(key)
}

fn control_hint_path_at(protected_root: &Path, project_root: &Path) -> Result<PathBuf> {
    let mut hash = Sha256::new();
    hash.update(b"franken-node/local-native-session-control-hint/v1\0");
    hash.update(project_key(project_root)?.as_bytes());
    Ok(protected_root.join(format!(
        "session-control-{}.page",
        hex::encode(hash.finalize())
    )))
}

/// The local inventory owner supplies this exact project-keyed hint path.
/// It is unrelated to a remote coordinator's configurable fleet state directory.
/// Absence or corruption is handled by periodic authoritative control rechecks.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn native_session_control_hint_path(project_root: &Path) -> Result<PathBuf> {
    control_hint_path_at(&inventory_root()?, project_root)
}

pub(crate) fn native_session_control_hint_path_at(
    protected_root: &Path,
    project_root: &Path,
) -> Result<PathBuf> {
    control_hint_path_at(protected_root, project_root)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn native_session_inventory_root() -> Result<PathBuf> {
    inventory_root()
}

/// Best-effort wakeup after a committed local fence transition. This cache is
/// never an admission ticket, a policy decision, or a quiescence certificate.
/// Failed publication must not turn an already committed mutation into an
/// ambiguous error; unchanged/missing pages leave the periodic check in force.
fn publish_control_hint(protected_root: &Path, report: &NativeSessionDrainReport) {
    let published = (|| -> Result<()> {
        validate_existing_forensic_directory(protected_root)?;
        let path = control_hint_path_at(protected_root, &report.project_root)?;
        // Do not leave a new temporary page on every reconciliation when a
        // persistent directory/device/symlink occupies this optional cache.
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
                bail!("native-session control hint must be a regular non-symlink file");
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect native-session control hint"),
        }
        let sequence = report
            .generation
            .checked_mul(2)
            .context("native-session control hint generation overflowed")?;
        let mut digest = [0_u8; 32];
        hex::decode_to_slice(
            &report.checkpoint.applied_actions.actions_sha256,
            &mut digest,
        )?;
        let snapshot = SeqlockControlSnapshot {
            // A local drain generation is only a change token, never a
            // distributed control epoch. Compare the complete snapshot: a
            // fence can be released without changing its generation.
            sequence,
            control_epoch: 0,
            quarantine_version: 0,
            active_hold_count: u64::from(report.checkpoint.fence_held),
            action_count: report.checkpoint.applied_actions.action_count,
            action_log_digest_prefix: digest,
        };
        if SeqlockControlPage::read_shared_page(&path).ok() != Some(snapshot) {
            SeqlockControlPage::write_shared_snapshot(&path, snapshot)?;
        }
        Ok(())
    })();
    if let Err(error) = published {
        tracing::warn!(error = %error,
            "native-session control hint unavailable; periodic authoritative checks remain active");
    }
}

/// Force a write conflict between admission and fence transitions, even if the
/// storage backend supplies snapshot rather than predicate serializability.
/// Reading different tables then writing disjoint rows would permit write
/// skew: a worker could otherwise be absent from a concurrently sealed census.
fn serialize_project_admission(tx: &mut Transaction<'_>, project_root: &Path) -> Result<()> {
    let key = SqliteValue::Text(project_key(project_root)?.to_owned().into());
    tx.execute_with_params(
        "INSERT INTO native_session_admission_serialization(project_root, transaction_nonce)
         VALUES (?1, ?2)
         ON CONFLICT(project_root) DO UPDATE SET transaction_nonce = excluded.transaction_nonce;",
        &[
            key,
            SqliteValue::Text(uuid::Uuid::now_v7().to_string().into()),
        ],
    )?;
    Ok(())
}

fn serialize_project_admissions(tx: &mut Transaction<'_>, scopes: &BTreeSet<&Path>) -> Result<()> {
    let mut keys = Vec::with_capacity(scopes.len());
    for scope in scopes {
        keys.push(project_key(scope)?);
    }
    if keys.is_empty() {
        return Ok(());
    }
    let nonce = uuid::Uuid::now_v7().to_string();
    let mut sql = String::from(
        "INSERT INTO native_session_admission_serialization(project_root, transaction_nonce) VALUES ",
    );
    let mut params = Vec::with_capacity(keys.len().saturating_mul(2));
    for (idx, key) in keys.into_iter().enumerate() {
        if idx > 0 {
            sql.push_str(", ");
        }
        let base = idx * 2 + 1;
        use std::fmt::Write as _;
        let _ = write!(sql, "(?{base}, ?{})", base + 1);
        params.push(SqliteValue::Text(key.to_owned().into()));
        params.push(SqliteValue::Text(nonce.clone().into()));
    }
    sql.push_str(
        " ON CONFLICT(project_root) DO UPDATE SET transaction_nonce = excluded.transaction_nonce;",
    );
    tx.execute_with_params(&sql, &params)?;
    Ok(())
}

fn drains_table_has_rows_unchecked(tx: &Transaction<'_>) -> Result<bool> {
    Ok(!tx
        .query("SELECT 1 FROM native_session_drains LIMIT 1;")?
        .is_empty())
}

fn drains_table_has_rows(tx: &Transaction<'_>) -> Result<bool> {
    if tx
        .query(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'native_session_drains';",
        )?
        .is_empty()
    {
        return Ok(false);
    }
    drains_table_has_rows_unchecked(tx)
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
    latest_drain_unchecked_table(tx, project_root, key)
}

fn latest_drain_unchecked_table(
    tx: &Transaction<'_>,
    project_root: &Path,
    key: &str,
) -> Result<Option<StoredNativeSessionDrain>> {
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

/// Preserve each project's latest unresolved census while compacting. Older
/// generations can remain marked held after a later generation supersedes them;
/// retaining all historical held rows would permanently prevent reclamation.
fn compaction_protected_sessions(
    tx: &Transaction<'_>,
    trusted_root: &ed25519_dalek::VerifyingKey,
) -> Result<BTreeSet<String>> {
    let mut protected = BTreeSet::new();
    if !drains_table_has_rows(tx)? {
        return Ok(protected);
    }
    check_retained_drain_byte_budget(tx)?;
    let projects = tx.query(&format!(
        "SELECT DISTINCT project_root FROM native_session_drains
         ORDER BY project_root LIMIT {};",
        MAX_RETAINED_DRAINS + 1,
    ))?;
    if projects.len() > MAX_RETAINED_DRAINS {
        bail!("native-session compaction drain census exceeds its project bound");
    }
    for row in projects {
        let [SqliteValue::Text(project)] = row.values() else {
            bail!("native-session compaction drain project is invalid");
        };
        let project: &str = project.as_ref();
        let project_root = Path::new(project);
        project_key(project_root)?;
        let drain = latest_drain_unchecked_table(tx, project_root, project)?
            .context("native-session drain disappeared during compaction snapshot")?;
        if drain.census_signature_hex.is_some() {
            drain.verify_census(trusted_root)?;
        }
        // Historical unsigned fences still retain obligations. An absent
        // signature cannot authorize removing their last supporting evidence.
        if drain.fence_held || !drain.actions_applied {
            protected.extend(drain.session_nonces);
        }
    }
    Ok(protected)
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

/// Admission revisions cover the selected root and every enclosing owner.
/// Each retained generation increases monotonically, so their checked sum
/// detects a drain-and-release cycle even when a child's generation is larger.
/// The public drain generation remains scoped to its exact control owner.
/// Return held fences and overflow as data so a raced admission can retain its
/// authenticated never-spawned outcome instead of an unresolved identity capture.
fn admission_scope_state_with_drains(
    tx: &Transaction<'_>,
    project_root: &Path,
    drains_has_rows: bool,
) -> Result<(Option<u64>, Option<String>)> {
    project_key(project_root)?;
    if !drains_has_rows {
        return Ok((Some(0), None));
    }
    let mut generation = Some(0_u64);
    let mut held_fence = None;
    for scope in project_root.ancestors() {
        let key = project_key(scope)?;
        if let Some(drain) = latest_drain_unchecked_table(tx, scope, key)? {
            generation = generation.and_then(|value| value.checked_add(drain.generation));
            if drain.fence_held && held_fence.is_none() {
                held_fence = Some(drain.drain_id);
            }
        }
    }
    Ok((generation, held_fence))
}

fn check_retained_drain_byte_budget(tx: &Transaction<'_>) -> Result<()> {
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
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InventoryFileFingerprint {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    len: u64,
    mtime: Option<std::time::SystemTime>,
}

impl InventoryFileFingerprint {
    fn same_identity_and_len(&self, other: &Self) -> bool {
        #[cfg(unix)]
        let same_inode = self.dev == other.dev && self.ino == other.ino;
        #[cfg(not(unix))]
        let same_inode = true;
        same_inode && self.len == other.len
    }
}

fn inventory_file_fingerprint(path: &Path) -> Option<InventoryFileFingerprint> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return None;
    }
    #[cfg(unix)]
    let (dev, ino) = {
        use std::os::unix::fs::MetadataExt as _;
        (metadata.dev(), metadata.ino())
    };
    Some(InventoryFileFingerprint {
        #[cfg(unix)]
        dev,
        #[cfg(unix)]
        ino,
        len: metadata.len(),
        mtime: metadata.modified().ok(),
    })
}

/// Pre-opened handle to an already-existing `native-sessions.db`, validated
/// against concurrent modification before reuse. Never creates files or
/// directories when the inventory is absent.
pub(crate) struct PreopenedNativeSessionInventory {
    protected_root: PathBuf,
    database_identity: Option<(u64, u64)>,
    db_fp: InventoryFileFingerprint,
    wal_fp: Option<InventoryFileFingerprint>,
    connection: Connection,
}

impl PreopenedNativeSessionInventory {
    fn is_fresh(&self) -> bool {
        let database_path = self.protected_root.join(INVENTORY_FILE);
        let wal_path = self.protected_root.join(format!("{INVENTORY_FILE}-wal"));
        inventory_file_fingerprint(&database_path) == Some(self.db_fp)
            && inventory_file_fingerprint(&wal_path) == self.wal_fp
    }
}

fn open_existing_inventory_for_prewarm_at(
    protected_root: &Path,
) -> Option<PreopenedNativeSessionInventory> {
    let database_path = protected_root.join(INVENTORY_FILE);
    if !validate_private_path_if_present(&database_path).ok()? {
        return None;
    }
    let wal_path = protected_root.join(format!("{INVENTORY_FILE}-wal"));
    let db_fp_before = inventory_file_fingerprint(&database_path)?;
    let wal_fp_before = inventory_file_fingerprint(&wal_path);
    let database_identity = path_file_identity(&database_path);
    let connection = open_inventory_unlocked(protected_root, false)
        .ok()
        .flatten()?;
    // `PRAGMA journal_mode=WAL` in fsqlite rewrites page 1 of `.db` in place
    // (updating `.db` mtime without changing `(dev, ino, len)` or `-wal`).
    // Confirm the DB kept its inode/length and `-wal` did not change during open,
    // then store post-open fingerprints for exact freshness checking before reuse.
    let db_fp_after = inventory_file_fingerprint(&database_path)?;
    let wal_fp_after = inventory_file_fingerprint(&wal_path);
    if !db_fp_before.same_identity_and_len(&db_fp_after) || wal_fp_before != wal_fp_after {
        return None;
    }
    Some(PreopenedNativeSessionInventory {
        protected_root: protected_root.to_path_buf(),
        database_identity,
        db_fp: db_fp_after,
        wal_fp: wal_fp_after,
        connection,
    })
}

/// Pre-open an already-existing `native-sessions.db` on the current thread
/// (since `fsqlite::Connection` is `!Send`), meant to run on the main thread
/// while `std::thread::scope` overlaps `Send + Sync` pre-admission checks and
/// `PrewarmedEvidenceWorker` overlaps `evidence-ledger.db` open. Never creates
/// files or directories when the inventory is absent.
pub(crate) fn preopen_existing_native_session_inventory() -> Option<PreopenedNativeSessionInventory>
{
    let root = existing_admission_root().ok().flatten()?;
    open_existing_inventory_for_prewarm_at(&root)
}

#[cfg_attr(not(test), allow(dead_code))]
fn admission_ticket_at(protected_root: &Path, project_root: &Path) -> Result<u64> {
    admission_ticket_with_connection_at_preopened(protected_root, project_root, None)
        .map(|ticket| ticket.generation)
}

#[cfg_attr(not(test), allow(dead_code))]
fn admission_ticket_with_connection_at(
    protected_root: &Path,
    project_root: &Path,
) -> Result<NativeSessionAdmissionTicket> {
    admission_ticket_with_connection_at_preopened(protected_root, project_root, None)
}

fn admission_ticket_with_connection_at_preopened(
    protected_root: &Path,
    project_root: &Path,
    mut preopened: Option<PreopenedNativeSessionInventory>,
) -> Result<NativeSessionAdmissionTicket> {
    project_key(project_root)?;
    let database_path = protected_root.join(INVENTORY_FILE);
    retry_snapshot_conflict(|| {
        let before_identity = path_file_identity(&database_path);
        let reused = preopened.take().filter(|pre| {
            pre.protected_root == protected_root
                && pre.database_identity == before_identity
                && pre.is_fresh()
        });
        let connection = match reused {
            Some(pre) => pre.connection,
            None => {
                let Some(connection) = open_inventory(protected_root, false)? else {
                    return Ok(NativeSessionAdmissionTicket::bare(0));
                };
                connection
            }
        };
        let (generation, held_fence, schema_verified) = {
            let mut tx = connection.transaction()?;
            let (schema_verified, has_drains_table) = inventory_tables_present(&tx)?;
            let drains_has_rows = has_drains_table && drains_table_has_rows_unchecked(&tx)?;
            let (generation, held_fence) =
                admission_scope_state_with_drains(&tx, project_root, drains_has_rows)?;
            tx.commit()?;
            (generation, held_fence, schema_verified)
        };
        protect_sidecars(protected_root)?;
        if let Some(drain_id) = held_fence {
            bail!("native-session admission is fenced by local fleet drain {drain_id}");
        }
        let generation =
            generation.context("native-session enclosing admission revision exhausted")?;
        let after_identity = path_file_identity(&database_path);
        let reusable_identity =
            before_identity.filter(|before| after_identity.as_ref() == Some(before));
        Ok(NativeSessionAdmissionTicket {
            generation,
            protected_root: reusable_identity.map(|_| protected_root.to_path_buf()),
            database_identity: reusable_identity,
            connection: reusable_identity.map(|_| connection),
            schema_verified,
        })
    })
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
/// enclosing revision in the same transaction that records the worker obligation.
/// An active ancestor fence also makes the live observer cancel old workers.
pub(crate) fn native_session_admission_ticket(project_root: &Path) -> Result<u64> {
    native_session_admission_ticket_with_preopened(project_root, None)
        .map(|ticket| ticket.generation)
}

/// Same contract as [`native_session_admission_ticket`], retaining the opened
/// inventory handle so immediate admission on the same database inode can reuse
/// the already-configured WAL connection instead of opening a second one.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn native_session_admission_ticket_with_connection(
    project_root: &Path,
) -> Result<NativeSessionAdmissionTicket> {
    native_session_admission_ticket_with_preopened(project_root, None)
}

/// Same contract as [`native_session_admission_ticket_with_connection`],
/// optionally reusing a background pre-opened connection when both `.db` and
/// `-wal` fingerprints are unchanged.
pub(crate) fn native_session_admission_ticket_with_preopened(
    project_root: &Path,
    preopened: Option<PreopenedNativeSessionInventory>,
) -> Result<NativeSessionAdmissionTicket> {
    project_key(project_root)?;
    let Some(root) = existing_admission_root()? else {
        return Ok(NativeSessionAdmissionTicket::bare(0));
    };
    admission_ticket_with_connection_at_preopened(&root, project_root, preopened)
}

/// Reference runtimes execute outside the native worker inventory, but they
/// must still honor its retained admission fences. Check every canonical
/// ancestor in one snapshot so staging or choosing a nested test cannot detach
/// a reference leg from its operator's maintenance hold. This is an admission
/// refusal, not a native-session registration or quiescence certificate.
pub(crate) fn enforce_reference_admission(project_root: &Path) -> Result<()> {
    project_key(project_root)?;
    let Some(root) = existing_admission_root()? else {
        return Ok(());
    };
    enforce_reference_admission_at(&root, project_root)
}

fn enforce_reference_admission_at(protected_root: &Path, project_root: &Path) -> Result<()> {
    // Validate even when the inventory has not been initialized yet.
    project_key(project_root)?;
    retry_snapshot_conflict(|| {
        let Some(connection) = open_inventory(protected_root, false)? else {
            return Ok(());
        };
        let mut tx = connection.transaction()?;
        if drains_table_has_rows(&tx)? {
            for scope in project_root.ancestors() {
                let key = project_key(scope)?;
                let drain = latest_drain_unchecked_table(&tx, scope, key)?;
                require_open_admission(drain.as_ref())?;
            }
        }
        tx.commit()?;
        protect_sidecars(protected_root)?;
        Ok(())
    })
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
            NativeSessionEffectObservation::NoAdmittedHostEffects,
        ) => {
            outcome.kind == NativeSessionOutcomeKind::Panicked
                && admission.process_spawn_authority_granted == Some(false)
        }
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
    let _write_lock = lock_inventory_file(protected_root, true)?;
    let report = retry_snapshot_conflict(|| {
        let fresh = open_inventory_unlocked(protected_root, true)?;
        let active_conn = fresh.as_ref().unwrap_or(&connection);
        let mut tx = active_conn.transaction()?;
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
            attested_checkpoint: None,
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
        check_retained_drain_byte_budget(&tx)?;
        tx.commit()?;
        Ok(report)
    })?;
    publish_control_hint(protected_root, &report);
    Ok(report)
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
    let _write_lock = lock_inventory_file(protected_root, false)?;
    let report = retry_snapshot_conflict(|| {
        let fresh = open_inventory_unlocked(protected_root, false)?;
        let active_conn = fresh.as_ref().unwrap_or(&connection);
        let mut tx = active_conn.transaction()?;
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
        protect_sidecars(protected_root)?;
        Ok(report)
    })?;
    publish_control_hint(protected_root, &report);
    Ok(report)
}

/// Authenticate a source-free supervisor observation from the retained
/// inventory, after rechecking the exact action snapshot and every signed
/// admission/outcome. Caller-provided counts are never signing inputs. Retain
/// mode preserves the exact signature of unchanged accounting across restarts;
/// refresh mode explicitly renews the observation for live transport guards.
///
/// This authenticates local accounting only. A released fence allows later
/// admissions, so the result cannot certify ongoing fleet quiescence.
pub fn attest_local_native_session_drain(
    project_root: &Path,
    node_id: &str,
    zone_id: &str,
    checkpoint: &FleetApplicationCheckpoint,
    mode: NativeSessionDrainAttestationMode,
) -> Result<NativeSessionDrainReport> {
    let project_root = project_root
        .canonicalize()
        .context("resolve native drain attestation project")?;
    let root = inventory_root()?;
    attest_drain_at(&root, &project_root, node_id, zone_id, checkpoint, mode)
}

fn attest_drain_at(
    protected_root: &Path,
    project_root: &Path,
    node_id: &str,
    zone_id: &str,
    checkpoint: &FleetApplicationCheckpoint,
    mode: NativeSessionDrainAttestationMode,
) -> Result<NativeSessionDrainReport> {
    use ed25519_dalek::Signer as _;

    retry_snapshot_conflict(|| read_inventory_at(protected_root, None))?;
    let connection = open_inventory(protected_root, false)?
        .context("native-session drain attestation requires its retained inventory")?;
    let root = load_runtime_evidence_product_root(
        &protected_root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH),
    )?;
    let _write_lock = lock_inventory_file(protected_root, false)?;
    retry_snapshot_conflict(|| {
        let fresh = open_inventory_unlocked(protected_root, false)?;
        let active_conn = fresh.as_ref().unwrap_or(&connection);
        let mut tx = active_conn.transaction()?;
        // Serialize with both admission and fence transitions. Do not freshly
        // sign an earlier read that can omit a newly committed session.
        serialize_project_admission(&mut tx, project_root)?;
        let mut drain = latest_drain(&tx, project_root)?
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
        let project_root_sha256 = hex::encode(digest.finalize());
        let checkpoint_sha256 = report.checkpoint.observation_sha256()?;
        let retained_attestation = drain
            .attested_checkpoint
            .as_ref()
            .map(|retained| -> Result<&NativeSessionDrainAttestation> {
                let attestation = retained
                    .supervisor_attestation
                    .as_ref()
                    .context("retained native-session drain observation has no attestation")?;
                attestation.verify(retained, node_id, zone_id, &root.verifying_key())?;
                if attestation.drain_id != drain.drain_id
                    || attestation.generation != drain.generation
                    || attestation.project_root_sha256 != project_root_sha256
                    || retained.applied_actions != drain.actions
                    || retained.session_set_sha256 != report.checkpoint.session_set_sha256
                    || retained.admitted_sessions != report.checkpoint.admitted_sessions
                {
                    bail!(
                        "retained native-session drain attestation does not match its sealed census"
                    );
                }
                Ok(attestation)
            })
            .transpose()?;
        let observation_changed = retained_attestation
            .is_none_or(|attestation| attestation.checkpoint_sha256 != checkpoint_sha256);
        if mode == NativeSessionDrainAttestationMode::Retain && !observation_changed {
            // Authentication and population coverage above still run on every
            // poll. Reuse never hides a missing receipt or changed obligation.
            report.checkpoint.supervisor_attestation = retained_attestation.cloned();
        } else {
            let mut attestation = NativeSessionDrainAttestation {
                schema_version: NATIVE_SESSION_DRAIN_ATTESTATION_SCHEMA.to_owned(),
                node_id: drain.node_id.clone(),
                zone_id: drain.zone_id.clone(),
                drain_id: drain.drain_id.clone(),
                generation: drain.generation,
                project_root_sha256,
                observed_at: Utc::now(),
                product_root_key_id: format!(
                    "ed25519:{}",
                    hex::encode(root.verifying_key().as_bytes())
                ),
                checkpoint_sha256,
                signature_hex: String::new(),
            };
            attestation.signature_hex =
                hex::encode(root.sign(&attestation.signing_payload()?).to_bytes());
            attestation.verify(&report.checkpoint, node_id, zone_id, &root.verifying_key())?;
            if let Some(previous) = retained_attestation {
                attestation.validate_successor_of(previous)?;
            }
            report.checkpoint.supervisor_attestation = Some(attestation);
            if observation_changed {
                // A transport renewal must not replace the original local
                // observation when its accounting has not changed.
                drain.attested_checkpoint = Some(report.checkpoint.clone());
                tx.execute_with_params(
                    "UPDATE native_session_drains SET state_json = ?1 WHERE drain_id = ?2;",
                    &[
                        SqliteValue::Text(bounded_json(&drain, MAX_DRAIN_BYTES)?.into()),
                        SqliteValue::Text(drain.drain_id.clone().into()),
                    ],
                )?;
                check_retained_drain_byte_budget(&tx)?;
            }
        }
        tx.commit()?;
        protect_sidecars(protected_root)?;
        Ok(report)
    })
}

/// Inspect retained payload bytes separately from pending-outcome reservations.
/// This bounded aggregate query remains usable at capacity; it does not decode
/// rows or treat unsigned database contents as lifecycle evidence.
pub fn read_local_native_session_capacity() -> Result<NativeSessionCapacityReport> {
    read_native_session_capacity_at(&inventory_root()?)
}

/// Recover only existing independently authenticated supervisor observations.
/// Missing receipts remain pending regardless of age, PID state or operator
/// invocation. Failed/interrupted outcomes retain their original uncertainty.
pub fn recover_local_native_session_capacity() -> Result<NativeSessionCapacityRecoveryReport> {
    recover_native_session_capacity_at(&inventory_root()?)
}

fn open_capacity_inventory_at(
    protected_root: &Path,
    read_only: bool,
) -> Result<Option<Connection>> {
    match std::fs::symlink_metadata(protected_root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect native-session capacity root"),
        Ok(_) => {}
    }
    if let Some(parent) = protected_root.parent() {
        validate_existing_forensic_directory(parent)?;
    }
    validate_existing_forensic_directory(protected_root)?;
    if !validate_forensic_inventory_paths(protected_root)? {
        return Ok(None);
    }
    if read_only {
        open_forensic_inventory(protected_root).map(Some)
    } else {
        open_inventory_unlocked(protected_root, false)
    }
}

fn capacity_report_in_transaction(
    protected_root: &Path,
    tx: &Transaction<'_>,
) -> Result<NativeSessionCapacityReport> {
    let rows = tx.query(CAPACITY_QUERY)?;
    let [row] = rows.as_slice() else {
        bail!("native-session capacity query returned an invalid row count");
    };
    capacity_report_from_values(protected_root, row.values())
}

fn capacity_report_from_values(
    protected_root: &Path,
    values: &[SqliteValue],
) -> Result<NativeSessionCapacityReport> {
    let [
        SqliteValue::Integer(count),
        SqliteValue::Integer(pending),
        SqliteValue::Integer(actual),
    ] = values
    else {
        bail!("native-session capacity query returned invalid accounting");
    };
    let retained_sessions = usize::try_from(*count)?;
    let pending_null_outcomes = usize::try_from(*pending)?;
    let actual_bytes = usize::try_from(*actual)?;
    let reserved_bytes = pending_null_outcomes
        .checked_mul(MAX_OUTCOME_BYTES)
        .and_then(|pending_bytes| actual_bytes.checked_add(pending_bytes))
        .context("native-session reservation accounting overflowed")?;
    let pct_full = retained_sessions
        .saturating_mul(100)
        .div_ceil(MAX_STORED_SESSIONS)
        .max(
            reserved_bytes
                .saturating_mul(100)
                .div_ceil(MAX_RESERVED_BYTES),
        );
    Ok(NativeSessionCapacityReport {
        store_present: true,
        retained_sessions,
        pending_null_outcomes,
        actual_bytes,
        reserved_bytes,
        pct_full,
        capacity_exceeded: retained_sessions > MAX_STORED_SESSIONS
            || reserved_bytes > MAX_RESERVED_BYTES,
        ..NativeSessionCapacityReport::absent(protected_root)
    })
}

fn read_native_session_capacity_at(protected_root: &Path) -> Result<NativeSessionCapacityReport> {
    let Some(connection) = open_capacity_inventory_at(protected_root, true)? else {
        return Ok(NativeSessionCapacityReport::absent(protected_root));
    };
    // The aggregate is one snapshot query through the existing read-only VFS.
    // Do not change journal mode, repair permissions or create a transaction.
    let rows = connection.query(CAPACITY_QUERY)?;
    let [row] = rows.as_slice() else {
        bail!("native-session capacity query returned an invalid row count");
    };
    capacity_report_from_values(protected_root, row.values())
}

fn recover_native_session_capacity_at(
    protected_root: &Path,
) -> Result<NativeSessionCapacityRecoveryReport> {
    let initial = read_native_session_capacity_at(protected_root)?;
    if !initial.store_present {
        return Ok(NativeSessionCapacityRecoveryReport {
            schema_version: "franken-node/native-session-capacity-recovery/v1".to_owned(),
            scope: "existing_signed_supervisor_outcomes_only".to_owned(),
            recovered_sessions: 0,
            reclaimed_reserved_bytes: 0,
            before: initial.clone(),
            after: initial,
            quiescence_certified: false,
        });
    }
    tracing::info!(
        event_code = "NSI_RECOVER_START",
        "authenticating retained supervisor outcomes before inventory recovery"
    );
    let _write_lock = lock_inventory_file(protected_root, false)?
        .context("native-session inventory disappeared before recovery")?;
    let report = retry_snapshot_conflict(|| {
        let connection = open_capacity_inventory_at(protected_root, false)?
            .context("native-session inventory disappeared before recovery")?;
        let mut tx = connection.transaction()?;
        let before = capacity_report_in_transaction(protected_root, &tx)?;
        // A stale projection may exceed its reservation budget even though
        // its actual payload is small. Bound the real allocation before
        // decoding, then enforce the original reservation cap before commit.
        // Receipt recovery also has its own aggregate byte bound.
        if before.retained_sessions > MAX_STORED_SESSIONS
            || before.actual_bytes > MAX_RESERVED_BYTES
        {
            bail!("native-session inventory payload exceeds the bounded recovery scan");
        }
        let records = read_records_in_transaction_matching(&tx, false)?;
        let recoveries = retained_outcome_recoveries(protected_root, &records)?;
        // All candidate signatures and admission bindings have passed before
        // the first update. Any conflicting row or failed commit rolls the
        // entire projection repair back; immutable evidence is never changed.
        for (admission, outcome) in &recoveries {
            write_observed_outcome(&mut tx, admission, outcome)?;
        }
        check_bounds(&tx)?;
        let after = capacity_report_in_transaction(protected_root, &tx)?;
        let recovered_sessions = recoveries.len();
        let reclaimed_reserved_bytes = before
            .reserved_bytes
            .checked_sub(after.reserved_bytes)
            .context("native-session recovery increased its reserved byte budget")?;
        tx.commit()?;
        protect_sidecars(protected_root)?;
        Ok(NativeSessionCapacityRecoveryReport {
            schema_version: "franken-node/native-session-capacity-recovery/v1".to_owned(),
            scope: "existing_signed_supervisor_outcomes_only".to_owned(),
            recovered_sessions,
            reclaimed_reserved_bytes,
            before,
            after,
            quiescence_certified: false,
        })
    })?;
    tracing::info!(
        event_code = "NSI_RECOVER_COMPLETE",
        recovered_sessions = report.recovered_sessions,
        reclaimed_reserved_bytes = report.reclaimed_reserved_bytes,
        pending_null_outcomes = report.after.pending_null_outcomes,
        "recovered exact signed outcomes; missing observations and fleet fences remain unresolved"
    );
    Ok(report)
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

/// Discover retained signed admissions and supervisor observations without
/// replaying a guest, repairing projections, provisioning keys or chmodding
/// evidence. Each record is independently authenticated; this live inspection
/// is not an atomic fleet census or a statement of historical completeness.
pub fn read_local_native_session_forensics(
    project_root: Option<&Path>,
) -> Result<NativeSessionForensicReport> {
    read_native_session_forensics_at(&inventory_root()?, project_root)
}

fn normalize_inventory_project_filter(project_root: Option<&Path>) -> Result<Option<PathBuf>> {
    project_root
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
        .transpose()
}

fn read_forensic_identity_captures(
    protected_root: &Path,
    key: &ed25519_dalek::VerifyingKey,
    admissions: &BTreeMap<String, NativeSessionAdmission>,
    report: &mut NativeSessionForensicReport,
) -> Result<()> {
    let directory = protected_root.join(RUNTIME_EVIDENCE_CAPTURE_DIR_RELATIVE_PATH);
    match std::fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("inspect retained native identity captures"),
        Ok(_) => validate_existing_forensic_directory(&directory)?,
    }
    let mut paths = std::fs::read_dir(&directory)?
        .take(MAX_IDENTITY_CAPTURES + 1)
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    if paths.len() > MAX_IDENTITY_CAPTURES {
        bail!("native identity capture inventory exceeds its bound; coverage is incomplete");
    }
    paths.sort();
    let mut seen = BTreeSet::new();
    for path in paths {
        let observed = (|| -> Result<RuntimeEvidenceIdentityCapture> {
            let bytes = read_runtime_evidence_private_file(&path, 64 * 1024)?;
            let capture: RuntimeEvidenceIdentityCapture = serde_json::from_slice(&bytes)?;
            capture.verify_with_product_root(key)?;
            if !seen.insert(capture.session_nonce.clone()) {
                bail!("native identity capture inventory repeats an authenticated session nonce");
            }
            if let Some(admission) = admissions.get(&capture.session_nonce)
                && (admission.identity_capture_path != path
                    || admission.product_root_key_id != capture.product_root_key_id
                    || admission.security_epoch
                        != capture
                            .evidence_verification_identity
                            .key_provenance
                            .activation_epoch
                            .as_u64())
            {
                bail!("native identity capture disagrees with its authenticated admission");
            }
            Ok(capture)
        })();
        match observed {
            Ok(capture) if !admissions.contains_key(&capture.session_nonce) => {
                report
                    .untracked_identity_captures
                    .push(UntrackedNativeIdentityCapture {
                        session_nonce: capture.session_nonce,
                        product_root_key_id: capture.product_root_key_id,
                        identity_capture_path: path,
                    });
            }
            Ok(_) => {}
            Err(error) => report.source_errors.push(forensic_source_error(
                None,
                path,
                NativeSessionForensicErrorKind::IdentityInventoryInvalid,
                format!("{error:#}"),
            )),
        }
    }
    report
        .untracked_identity_captures
        .sort_by(|left, right| left.session_nonce.cmp(&right.session_nonce));
    Ok(())
}

/// Enumerate bounded lookup selectors, not trusted identities. Every selected
/// body is authenticated against the original root before it enters the report.
fn read_retained_forensic_selectors(
    protected_root: &Path,
    max_files: usize,
    max_bytes: usize,
    report: &mut NativeSessionForensicReport,
) -> Result<BTreeSet<String>> {
    let directory = protected_root.join(ADMISSION_RECORD_DIRECTORY);
    match std::fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(error) => return Err(error).context("inspect retained native-session admissions"),
        Ok(_) => validate_existing_forensic_directory(&directory)?,
    }
    let mut paths = std::fs::read_dir(&directory)?
        .take(max_files.saturating_add(1))
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    if paths.len() > max_files {
        bail!("retained native-session forensic admissions exceed their file bound");
    }
    paths.sort();
    let mut selectors = BTreeSet::new();
    let mut scanned_bytes = 0usize;
    for path in paths {
        let selector = (|| -> Result<String> {
            let bytes = read_runtime_evidence_private_file(&path, MAX_ADMISSION_BYTES)?;
            scanned_bytes = scanned_bytes.saturating_add(bytes.len());
            if scanned_bytes > max_bytes {
                bail!("retained native-session forensic admissions exceed their byte bound");
            }
            let admission: NativeSessionAdmission = serde_json::from_slice(&bytes)
                .context("decode retained native-session forensic selector")?;
            validate_forensic_session_nonce(&admission.session_nonce)?;
            if path != admission_record_path(protected_root, &admission.session_nonce) {
                bail!("retained native-session admission filename disagrees with its nonce");
            }
            Ok(admission.session_nonce)
        })();
        match selector {
            Ok(nonce) => {
                selectors.insert(nonce);
            }
            Err(error) => report.source_errors.push(forensic_source_error(
                None,
                path,
                NativeSessionForensicErrorKind::AdmissionRecordInvalid,
                format!("{error:#}"),
            )),
        }
        if scanned_bytes > max_bytes {
            bail!("retained native-session forensic admission scan exceeded its byte bound");
        }
    }
    Ok(selectors)
}

/// Preserve the same outcome/source/journal verification for database-backed
/// admissions and immutable admissions recovered from a missing projection.
fn append_native_session_forensic_observation(
    protected_root: &Path,
    key: &ed25519_dalek::VerifyingKey,
    admission: NativeSessionAdmission,
    admission_receipt: NativeSessionAdmissionReceipt,
    projection: (SqliteValue, bool),
    retained_bytes: &mut usize,
    report: &mut NativeSessionForensicReport,
) -> Result<()> {
    let (projected_outcome, outcome_within_bound) = projection;
    let nonce = admission.session_nonce.clone();
    let mut record = NativeSessionForensicRecord {
        admission_receipt_path: admission_receipt_path(protected_root, &nonce),
        admission,
        outcome: None,
        status: NativeSessionForensicStatus::PendingLivenessUnknown,
        outcome_receipt_path: None,
        outcome_recovered_from_receipt: false,
        durable_journal: None,
    };
    let outcome = authenticate_forensic_outcome(
        protected_root,
        &record.admission,
        &projected_outcome,
        outcome_within_bound,
        key,
    );
    let mut signed_outcome = None;
    match outcome {
        Ok(Some(receipt)) => {
            let signed_bytes = bounded_json(&receipt.outcome, MAX_OUTCOME_BYTES)?.len();
            let projected_bytes = match &projected_outcome {
                SqliteValue::Text(text) => text.len(),
                _ => 0,
            };
            *retained_bytes =
                retained_bytes.saturating_add(signed_bytes.saturating_sub(projected_bytes));
            if *retained_bytes > MAX_RESERVED_BYTES {
                report.source_errors.push(forensic_source_error(
                    Some(&nonce),
                    report.database_path.clone(),
                    NativeSessionForensicErrorKind::InventoryUnreadable,
                    "native-session forensic receipts exceed the aggregate byte bound",
                ));
                record.status = NativeSessionForensicStatus::OutcomeUnverified;
                report.records.push(record);
                return Ok(());
            }
            record.status = if receipt.outcome.kind
                == NativeSessionOutcomeKind::SupervisionIncomplete
                || receipt.outcome.process != NativeSessionProcessObservation::WorkerReaped
            {
                NativeSessionForensicStatus::SupervisionIncomplete
            } else {
                NativeSessionForensicStatus::TerminalObservation
            };
            record.outcome_recovered_from_receipt = matches!(projected_outcome, SqliteValue::Null);
            record.outcome_receipt_path = Some(outcome_receipt_path(protected_root, &nonce));
            signed_outcome = Some(
                frankenengine_verifier_sdk::native_session::NativeSessionForensicOutcome {
                    payload_json: receipt.payload_json()?,
                    signature_hex: receipt.signature_hex,
                },
            );
            record.outcome = Some(receipt.outcome);
        }
        Ok(None) if matches!(projected_outcome, SqliteValue::Null) => {}
        Ok(None) => {
            record.status = NativeSessionForensicStatus::OutcomeUnverified;
            report.source_errors.push(forensic_source_error(
                Some(&nonce),
                outcome_receipt_path(protected_root, &nonce),
                NativeSessionForensicErrorKind::OutcomeReceiptMissing,
                "database outcome has no authenticated supervisor receipt",
            ));
        }
        Err(error) => {
            record.status = NativeSessionForensicStatus::OutcomeUnverified;
            report.source_errors.push(error);
        }
    }
    // Charge authenticated sizes before reading the corresponding objects.
    if let Some(source) = &record.admission.source_capsule {
        *retained_bytes = retained_bytes.saturating_add(source.capsule_bytes);
        if *retained_bytes > MAX_RESERVED_BYTES {
            report.source_errors.push(forensic_source_error(
                Some(&nonce),
                protected_root.join(SOURCE_CAPSULE_DIRECTORY),
                NativeSessionForensicErrorKind::SourceCapsuleInvalid,
                "native-session forensic sources exceed the aggregate byte bound",
            ));
            report.records.push(record);
            return Ok(());
        }
    }
    let source_capsule =
        match read_retained_native_session_source_capsule(protected_root, &record.admission) {
            Ok(source) => source,
            Err(error) => {
                report.source_errors.push(forensic_source_error(
                    Some(&nonce),
                    protected_root.join(SOURCE_CAPSULE_DIRECTORY),
                    NativeSessionForensicErrorKind::SourceCapsuleInvalid,
                    format!("{error:#}"),
                ));
                report.records.push(record);
                return Ok(());
            }
        };
    let journal =
        read_retained_native_session_effect_journal(protected_root, &nonce).and_then(|journal| {
            journal
                .map(|jsonl| {
                    *retained_bytes = retained_bytes.saturating_add(jsonl.len());
                    if *retained_bytes > MAX_RESERVED_BYTES {
                        bail!("native-session forensic journals exceed the aggregate byte bound");
                    }
                    let (bundle, byte_cap) = make_native_session_forensic_bundle(
                        &record.admission,
                        &admission_receipt,
                        signed_outcome,
                        Some(jsonl),
                        source_capsule.as_ref().map(|bytes| bytes.as_slice()),
                    )?;
                    let bytes = bounded_json(&bundle, byte_cap)?;
                    let verified =
                        frankenengine_verifier_sdk::native_session::verify_native_session_forensics(
                            bytes.as_bytes(),
                            key,
                        )?;
                    verified
                        .durable_journal
                        .map(NativeSessionForensicJournal::from)
                        .context("verified forensic bundle has no durable journal")
                })
                .transpose()
        });
    match journal {
        Ok(journal) => record.durable_journal = journal,
        Err(error) => report.source_errors.push(forensic_source_error(
            Some(&nonce),
            super::native_session_journal::native_session_effect_journal_path(
                protected_root,
                &nonce,
            ),
            NativeSessionForensicErrorKind::JournalInvalid,
            format!("{error:#}"),
        )),
    }
    report.records.push(record);
    Ok(())
}

fn validate_archived_hot_residue(
    protected_root: &Path,
    key: &ed25519_dalek::VerifyingKey,
    entry: &NativeSessionColdArchiveEntry,
    retained_bytes: &mut usize,
) -> Result<Option<NativeSessionForensicJournal>> {
    let admission = &entry.admission;
    let body_path = admission_record_path(protected_root, &entry.session_nonce);
    if validate_private_path_if_present(&body_path)? {
        let body = read_runtime_evidence_private_file(&body_path, MAX_ADMISSION_BYTES)?;
        *retained_bytes = retained_bytes.saturating_add(body.len());
        if bounded_json(admission, MAX_ADMISSION_BYTES)?.as_bytes() != body.as_slice() {
            bail!("retired hot admission body disagrees with its authenticated cold archive");
        }
    }
    // Absence is expected after partial retirement. Every remaining signed
    // receipt must still authenticate against the exact archived admission.
    read_admission_receipt(protected_root, admission, key)?;
    if let Some(receipt) = read_outcome_receipt(protected_root, admission, key)? {
        *retained_bytes =
            retained_bytes.saturating_add(bounded_json(&receipt.outcome, MAX_OUTCOME_BYTES)?.len());
        if receipt.outcome != entry.outcome {
            bail!("retired hot outcome disagrees with its authenticated cold archive");
        }
    }
    if validate_private_path_if_present(&admission.identity_capture_path)? {
        let bytes =
            read_runtime_evidence_private_file(&admission.identity_capture_path, 64 * 1024)?;
        *retained_bytes = retained_bytes.saturating_add(bytes.len());
        let capture: RuntimeEvidenceIdentityCapture = serde_json::from_slice(&bytes)?;
        verify_capture_for_admission(admission, &capture, key)?;
        if entry.identity_capture.as_ref() != Some(&capture) {
            bail!("retired hot identity disagrees with its authenticated cold archive");
        }
    }
    let journal =
        read_retained_native_session_effect_journal(protected_root, &entry.session_nonce)?;
    if let Some(journal) = &journal {
        *retained_bytes = retained_bytes.saturating_add(journal.len());
    }
    if *retained_bytes > MAX_RESERVED_BYTES {
        bail!("retired hot evidence exceeds the forensic aggregate byte bound");
    }
    journal
        .map(|journal| {
            frankenengine_verifier_sdk::native_session::verify_native_session_effect_journal(
                journal.as_bytes(),
                key,
                &entry.session_nonce,
                &admission_digest(admission)?,
            )
            .map(NativeSessionForensicJournal::from)
            .map_err(anyhow::Error::from)
        })
        .transpose()
}

fn append_archived_forensic_observations(
    protected_root: &Path,
    key: &ed25519_dalek::VerifyingKey,
    archived: RetainedColdArchiveEvidence,
    admissions: &mut BTreeMap<String, NativeSessionAdmission>,
    retained_bytes: &mut usize,
    report: &mut NativeSessionForensicReport,
) -> Result<()> {
    let mut checked_sources = BTreeSet::new();
    for (nonce, (path, entry)) in archived.entries {
        if *retained_bytes > MAX_RESERVED_BYTES {
            bail!("native-session forensic evidence exceeds the aggregate byte bound");
        }
        if let Some(hot_admission) = admissions.get(&nonce) {
            if hot_admission != &entry.admission {
                bail!("hot and archived native-session admissions disagree");
            }
            let hot_outcome = read_outcome_receipt(protected_root, hot_admission, key)?.context(
                "archived native session has a hot admission without its signed outcome",
            )?;
            if hot_outcome.outcome != entry.outcome {
                bail!("hot and archived native-session outcomes disagree");
            }
            let capture_bytes = read_runtime_evidence_private_file(
                &hot_admission.identity_capture_path,
                64 * 1024,
            )?;
            let hot_capture: RuntimeEvidenceIdentityCapture =
                serde_json::from_slice(&capture_bytes)?;
            if entry.identity_capture.as_ref() != Some(&hot_capture) {
                bail!("hot and archived native-session identities disagree");
            }
            // A crash after archive publication but before hot retirement may
            // leave both exact copies. Preserve one original hot observation,
            // including any existing projection or journal diagnostics.
            continue;
        }
        admissions.insert(nonce, entry.admission.clone());
        if report
            .project_root
            .as_ref()
            .is_some_and(|project| !entry.admission.belongs_to_control_scope(project))
        {
            continue;
        }
        let durable_journal =
            match validate_archived_hot_residue(protected_root, key, &entry, retained_bytes) {
                Ok(journal) => journal,
                Err(error) => {
                    report.source_errors.push(forensic_source_error(
                        Some(&entry.session_nonce),
                        path.clone(),
                        NativeSessionForensicErrorKind::ColdArchiveInvalid,
                        format!("{error:#}"),
                    ));
                    None
                }
            };
        if let Some(source) = &entry.admission.source_capsule
            && checked_sources.insert(source.capsule_digest.clone())
        {
            *retained_bytes = retained_bytes.saturating_add(source.capsule_bytes);
            if *retained_bytes > MAX_RESERVED_BYTES {
                bail!("native-session forensic sources exceed the aggregate byte bound");
            }
            read_retained_native_session_source_capsule(protected_root, &entry.admission)?;
        }
        report.records.push(NativeSessionForensicRecord {
            admission: entry.admission,
            outcome: Some(entry.outcome),
            status: NativeSessionForensicStatus::TerminalObservation,
            admission_receipt_path: path.clone(),
            outcome_receipt_path: Some(path),
            outcome_recovered_from_receipt: true,
            durable_journal,
        });
    }
    Ok(())
}

fn read_native_session_forensics_at(
    protected_root: &Path,
    project_root: Option<&Path>,
) -> Result<NativeSessionForensicReport> {
    let mut report = NativeSessionForensicReport {
        schema_version: FORENSIC_INVENTORY_SCHEMA.to_owned(),
        scope: "authenticated_local_supervisor_observation".to_owned(),
        coverage: "retained_observations_only_not_historical_completeness".to_owned(),
        database_path: protected_root.join(INVENTORY_FILE),
        store_present: false,
        project_root: normalize_inventory_project_filter(project_root)?,
        records: Vec::new(),
        source_errors: Vec::new(),
        untracked_identity_captures: Vec::new(),
        replay_certified: false,
        quiescence_certified: false,
    };
    match std::fs::symlink_metadata(protected_root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(report),
        Err(error) => return Err(error).context("inspect native-session protected state root"),
        Ok(_) => {}
    }
    if let Some(product_root) = protected_root.parent() {
        validate_existing_forensic_directory(product_root)?;
    }
    validate_existing_forensic_directory(protected_root)?;
    validate_existing_forensic_directory(&protected_root.join("keys"))?;
    for name in [
        ADMISSION_RECEIPT_DIRECTORY,
        ADMISSION_RECORD_DIRECTORY,
        OUTCOME_RECEIPT_DIRECTORY,
    ] {
        let directory = protected_root.join(name);
        match std::fs::symlink_metadata(&directory) {
            Ok(_) => validate_existing_forensic_directory(&directory)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect retained native-session receipts"),
        }
    }
    let root = load_runtime_evidence_product_root(
        &protected_root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH),
    )?;
    let key = root.verifying_key();
    drop(root);
    let archived = match read_retained_cold_archives(protected_root, &key) {
        Ok(archived) => archived,
        Err(error) => {
            report.source_errors.push(forensic_source_error(
                None,
                protected_root.join(COLD_ARCHIVE_DIRECTORY),
                NativeSessionForensicErrorKind::ColdArchiveInvalid,
                format!("{error:#}"),
            ));
            RetainedColdArchiveEvidence::default()
        }
    };
    let mut admissions = BTreeMap::new();
    let inventory = (|| -> Result<Option<Connection>> {
        match std::fs::symlink_metadata(&report.database_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect retained native-session database"),
            Ok(_) => report.store_present = true,
        }
        // Validate orphaned sidecars even if the main file is missing. An
        // unsafe filesystem object must never enable immutable-body fallback.
        let present = validate_forensic_inventory_paths(protected_root)?;
        if present != report.store_present {
            bail!("native-session forensic database changed during path validation");
        }
        if !present {
            return Ok(None);
        }
        open_forensic_inventory(protected_root).map(Some)
    })();
    let (inventory, mut allow_retained_discovery) = match inventory {
        Ok(connection) => (connection, true),
        Err(error) => {
            let allowed = error
                .downcast_ref::<NativeSessionForensicInventoryUnavailable>()
                .is_some();
            report.source_errors.push(forensic_source_error(
                None,
                report.database_path.clone(),
                NativeSessionForensicErrorKind::InventoryUnreadable,
                format!("{error:#}"),
            ));
            (None, allowed)
        }
    };
    let mut selectors = BTreeSet::new();
    if let Some(connection) = inventory.as_ref() {
        let census = (|| -> Result<_> {
            let rows = connection
                .query(&format!(
                    "SELECT CASE WHEN typeof(session_nonce) = 'text'
                                  AND LENGTH(CAST(session_nonce AS BLOB)) <= 128
                                 THEN session_nonce ELSE NULL END
                     FROM native_sessions LIMIT {};",
                    MAX_STORED_SESSIONS + 1,
                ))
                .map_err(|error| {
                    classify_forensic_inventory_read_error(
                        "enumerate retained native-session inventory",
                        error,
                    )
                })?;
            if rows.len() > MAX_STORED_SESSIONS {
                bail!("native-session forensic inventory exceeds its session bound");
            }
            Ok(rows)
        })();
        match census {
            Err(error) => {
                allow_retained_discovery = error
                    .downcast_ref::<NativeSessionForensicInventoryUnavailable>()
                    .is_some();
                report.source_errors.push(forensic_source_error(
                    None,
                    report.database_path.clone(),
                    NativeSessionForensicErrorKind::InventoryUnreadable,
                    format!("{error:#}"),
                ));
            }
            Ok(rows) => {
                for row in rows {
                    let [SqliteValue::Text(nonce)] = row.values() else {
                        report.source_errors.push(forensic_source_error(
                            None,
                            report.database_path.clone(),
                            NativeSessionForensicErrorKind::AdmissionInvalid,
                            "native-session forensic inventory has an invalid nonce column",
                        ));
                        continue;
                    };
                    if let Err(error) = validate_forensic_session_nonce(nonce) {
                        report.source_errors.push(forensic_source_error(
                            Some(nonce),
                            report.database_path.clone(),
                            NativeSessionForensicErrorKind::AdmissionInvalid,
                            format!("{error:#}"),
                        ));
                        continue;
                    }
                    selectors.insert(nonce.to_string());
                }
            }
        }
    }
    if allow_retained_discovery {
        match read_retained_forensic_selectors(
            protected_root,
            MAX_STORED_SESSIONS,
            MAX_RETAINED_ADMISSION_BYTES,
            &mut report,
        ) {
            Ok(retained) => {
                if !report.store_present && !retained.is_empty() {
                    report.source_errors.push(forensic_source_error(
                        None,
                        report.database_path.clone(),
                        NativeSessionForensicErrorKind::InventoryUnreadable,
                        "native-session inventory is missing; only retained signed observations are available",
                    ));
                }
                selectors.extend(retained);
            }
            Err(error) => report.source_errors.push(forensic_source_error(
                None,
                protected_root.join(ADMISSION_RECORD_DIRECTORY),
                NativeSessionForensicErrorKind::AdmissionRecordInvalid,
                format!("{error:#}"),
            )),
        }
    }
    if selectors.len() > MAX_STORED_SESSIONS {
        report.source_errors.push(forensic_source_error(
            None,
            report.database_path.clone(),
            NativeSessionForensicErrorKind::InventoryUnreadable,
            "combined native-session forensic inventory exceeds its session bound; coverage is incomplete",
        ));
    }
    let mut retained_bytes = 0usize;
    for nonce in selectors.iter().take(MAX_STORED_SESSIONS) {
        let projection = if let Some(connection) = inventory.as_ref() {
            match read_optional_forensic_projection(connection, nonce) {
                Ok(Some(projection)) => Some(projection),
                Ok(None) => {
                    if !archived.entries.contains_key(nonce) {
                        report.source_errors.push(forensic_source_error(
                            Some(nonce),
                            report.database_path.clone(),
                            NativeSessionForensicErrorKind::InventoryUnreadable,
                            "retained native-session admission has no database projection",
                        ));
                    }
                    None
                }
                Err(error) => {
                    let unavailable = error
                        .downcast_ref::<NativeSessionForensicInventoryUnavailable>()
                        .is_some();
                    report.source_errors.push(forensic_source_error(
                        Some(nonce),
                        report.database_path.clone(),
                        if unavailable {
                            NativeSessionForensicErrorKind::InventoryUnreadable
                        } else {
                            NativeSessionForensicErrorKind::AdmissionInvalid
                        },
                        format!("{error:#}"),
                    ));
                    if !unavailable {
                        continue;
                    }
                    // Preserve export's safety boundary on a damaged database:
                    // disappearance, access/identity errors and unsafe sidecars
                    // cannot be reclassified as readable corrupt evidence.
                    let safety_error = match validate_forensic_inventory_paths(protected_root) {
                        Ok(true) => None,
                        Ok(false) => Some(
                            "native-session forensic database disappeared while reading".to_owned(),
                        ),
                        Err(error) => Some(format!("{error:#}")),
                    };
                    if let Some(detail) = safety_error {
                        report.source_errors.push(forensic_source_error(
                            Some(nonce),
                            report.database_path.clone(),
                            NativeSessionForensicErrorKind::InventoryUnreadable,
                            detail,
                        ));
                        continue;
                    }
                    None
                }
            }
        } else if allow_retained_discovery {
            None
        } else {
            continue;
        };
        if projection.is_none() && archived.entries.contains_key(nonce) {
            // The signed cold copy explains this exact row's retirement.
            // Validate any residual hot files in the archive pass below;
            // missing originals must not be fabricated or required again.
            continue;
        }
        let (admission, receipt, projected_outcome, outcome_within_bound) = match projection {
            Some((admission_value, projected_outcome, outcome_within_bound)) => {
                let json_bytes = |value: &SqliteValue| match value {
                    SqliteValue::Text(text) => text.len(),
                    _ => 0,
                };
                retained_bytes = retained_bytes
                    .saturating_add(json_bytes(&admission_value))
                    .saturating_add(json_bytes(&projected_outcome));
                if retained_bytes > MAX_RESERVED_BYTES {
                    report.source_errors.push(forensic_source_error(
                        Some(nonce),
                        report.database_path.clone(),
                        NativeSessionForensicErrorKind::InventoryUnreadable,
                        "native-session forensic inventory exceeds its aggregate byte bound",
                    ));
                    break;
                }
                let (admission, receipt) = match authenticate_forensic_admission(
                    protected_root,
                    nonce,
                    &admission_value,
                    &key,
                ) {
                    Ok(authenticated) => authenticated,
                    Err(error) => {
                        report.source_errors.push(error);
                        continue;
                    }
                };
                (admission, receipt, projected_outcome, outcome_within_bound)
            }
            None => {
                let retained = read_retained_admission_record(protected_root, nonce, &key)
                    .and_then(|record| {
                        record.context(
                            "native-session forensic discovery requires an original signed admission body when its projection is unavailable",
                        )
                    });
                let (admission, receipt) = match retained {
                    Ok(authenticated) => authenticated,
                    Err(error) => {
                        report.source_errors.push(forensic_source_error(
                            Some(nonce),
                            admission_record_path(protected_root, nonce),
                            NativeSessionForensicErrorKind::AdmissionRecordInvalid,
                            format!("{error:#}"),
                        ));
                        continue;
                    }
                };
                retained_bytes = retained_bytes
                    .saturating_add(bounded_json(&admission, MAX_ADMISSION_BYTES)?.len());
                if retained_bytes > MAX_RESERVED_BYTES {
                    report.source_errors.push(forensic_source_error(
                        Some(nonce),
                        admission_record_path(protected_root, nonce),
                        NativeSessionForensicErrorKind::InventoryUnreadable,
                        "native-session forensic admissions exceed the aggregate byte bound",
                    ));
                    break;
                }
                (admission, receipt, SqliteValue::Null, true)
            }
        };
        // Authenticate before filtering: unsigned scope changes must stay
        // visible, and valid out-of-scope admissions are not identity orphans.
        admissions.insert(admission.session_nonce.clone(), admission.clone());
        if report
            .project_root
            .as_ref()
            .is_some_and(|project| !admission.belongs_to_control_scope(project))
        {
            continue;
        }
        append_native_session_forensic_observation(
            protected_root,
            &key,
            admission,
            receipt,
            (projected_outcome, outcome_within_bound),
            &mut retained_bytes,
            &mut report,
        )?;
        if retained_bytes > MAX_RESERVED_BYTES {
            break;
        }
    }
    if let Err(error) = append_archived_forensic_observations(
        protected_root,
        &key,
        archived,
        &mut admissions,
        &mut retained_bytes,
        &mut report,
    ) {
        report.source_errors.push(forensic_source_error(
            None,
            protected_root.join(COLD_ARCHIVE_DIRECTORY),
            NativeSessionForensicErrorKind::ColdArchiveInvalid,
            format!("{error:#}"),
        ));
    }
    report.records.sort_by(|left, right| {
        left.admission
            .session_nonce
            .cmp(&right.admission.session_nonce)
    });
    if let Err(error) =
        read_forensic_identity_captures(protected_root, &key, &admissions, &mut report)
    {
        report.source_errors.push(forensic_source_error(
            None,
            protected_root.join(RUNTIME_EVIDENCE_CAPTURE_DIR_RELATIVE_PATH),
            NativeSessionForensicErrorKind::IdentityInventoryInvalid,
            format!("{error:#}"),
        ));
    }
    Ok(report)
}

/// Availability of the selected admission in the mutable inventory. A matching
/// admission says nothing about live processes, complete history or whether an
/// unsigned outcome projection is authoritative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSessionForensicProjection {
    Matched,
    MissingDatabase,
    MissingAdmission,
    UnreadableDatabase,
}

impl NativeSessionForensicProjection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::MissingDatabase => "missing_database",
            Self::MissingAdmission => "missing_admission",
            Self::UnreadableDatabase => "unreadable_database",
        }
    }
}

/// Portable evidence plus the SDK verdict established against the existing
/// local product root. The bundle does not provide its own trust anchor.
pub struct NativeSessionForensicExport {
    pub bundle: frankenengine_verifier_sdk::native_session::NativeSessionForensicBundle,
    pub verification: frankenengine_verifier_sdk::native_session::VerifiedNativeSessionForensics,
    pub inventory_projection: NativeSessionForensicProjection,
    /// Present only for an unreadable SQLite projection, bounded to 4096 UTF-8
    /// bytes. This local diagnostic is not signed evidence or a recovery claim.
    pub inventory_diagnostic: Option<String>,
}

/// Export one retained signed admission and its optional signed supervisor
/// observation. Missing terminal evidence remains explicitly pending, even if
/// an unsigned database projection claims completion. This operation neither
/// recovers the database nor creates or signs authority, and does not require
/// the original project to remain on disk. A missing/unreadable projection may
/// use the original immutable admission body; present contradictions are fatal.
/// It establishes no native replay, fleet quiescence, external-effect commit
/// status or historical completeness.
pub fn export_local_native_session_forensics(nonce: &str) -> Result<NativeSessionForensicExport> {
    validate_forensic_session_nonce(nonce)?;
    export_native_session_forensics_at(&inventory_root()?, nonce)
}

fn validate_forensic_session_nonce(nonce: &str) -> Result<()> {
    let parsed = uuid::Uuid::parse_str(nonce).context("invalid native-session forensic nonce")?;
    if parsed.to_string() != nonce || parsed.is_nil() {
        bail!("native-session forensic nonce must be a canonical non-nil UUID");
    }
    Ok(())
}

/// Unlike ensure_runtime_evidence_directory, a forensic read must not repair
/// permissions, create a missing component or turn absence into authority.
fn validate_existing_forensic_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).with_context(|| {
        format!(
            "inspect retained native-session directory {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("native-session forensic evidence requires an existing non-symlink directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            bail!("native-session forensic evidence directory must be private and owned");
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if metadata.file_attributes() & 0x0000_0400 != 0 {
            bail!("native-session forensic evidence directory must not be a reparse point");
        }
    }
    Ok(())
}

fn validate_forensic_inventory_paths(protected_root: &Path) -> Result<bool> {
    let present = validate_private_path_if_present(&protected_root.join(INVENTORY_FILE))?;
    // Unsafe orphaned sidecars remain errors even when the main file is gone.
    for suffix in ["-wal", "-shm", "-journal"] {
        validate_private_path_if_present(
            &protected_root.join(format!("{INVENTORY_FILE}{suffix}")),
        )?;
    }
    Ok(present)
}

/// Only a SQLite read failure may enable immutable-evidence fallback. Filesystem
/// safety failures and readable contradictory rows never receive this type.
#[derive(Debug)]
struct NativeSessionForensicInventoryUnavailable {
    detail: String,
}

impl NativeSessionForensicInventoryUnavailable {
    fn new(detail: impl std::fmt::Display) -> Self {
        Self {
            detail: bounded_forensic_diagnostic(detail),
        }
    }
}

impl std::fmt::Display for NativeSessionForensicInventoryUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for NativeSessionForensicInventoryUnavailable {}

fn classify_forensic_inventory_read_error(
    context: &'static str,
    error: fsqlite::FrankenError,
) -> anyhow::Error {
    use fsqlite::FrankenError;

    // CannotOpen includes an expected-descriptor identity mismatch. Generic
    // I/O, access, locking, limit and internal failures likewise remain fatal;
    // they cannot be assumed to mean safely readable-but-corrupt evidence.
    if matches!(
        &error,
        FrankenError::DatabaseCorrupt { .. }
            | FrankenError::NotADatabase { .. }
            | FrankenError::WalCorrupt { .. }
            | FrankenError::ShortRead { .. }
            | FrankenError::IoRead { .. }
            | FrankenError::NoSuchTable { .. }
            | FrankenError::NoSuchColumn { .. }
            | FrankenError::ParseError { .. }
            | FrankenError::SyntaxError { .. }
    ) {
        NativeSessionForensicInventoryUnavailable::new(format!("{context}: {error}")).into()
    } else {
        anyhow::Error::new(error).context(context)
    }
}

fn open_forensic_inventory(protected_root: &Path) -> Result<Connection> {
    let path = protected_root.join(INVENTORY_FILE);
    if !validate_forensic_inventory_paths(protected_root)? {
        bail!("native-session forensic export requires an existing admission database");
    }
    let name = path
        .to_str()
        .context("native-session forensic database path must be UTF-8")?;
    // Bind the read-only VFS handle to a retained no-follow descriptor. Do not
    // use open_inventory(false): it configures WAL and repairs sidecar modes.
    #[cfg(unix)]
    let file = {
        use rustix::fs::{Mode, OFlags, open};
        std::fs::File::from(open(
            &path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?)
    };
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x0020_0000)
            .share_mode(0x0000_0003)
            .open(&path)?
    };
    #[cfg(not(any(unix, windows)))]
    let file = std::fs::File::open(&path)?;
    let metadata = file.metadata()?;
    validate_runtime_evidence_private_file_metadata(&path, &metadata)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 || metadata.uid() != rustix::process::geteuid().as_raw() {
            bail!("native-session forensic database must be owned and have a single link");
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if metadata.file_attributes() & 0x0000_0400 != 0 {
            bail!("native-session forensic database must not be a reparse point");
        }
    }
    let identity = fsqlite::FileIdentity::from_file(&file)?
        .context("native-session forensic database identity is unavailable")?;
    let connection = match Connection::open_schema_only_with_expected_identity(name, identity) {
        Ok(connection) => connection,
        Err(error) => {
            if !validate_forensic_inventory_paths(protected_root)? {
                bail!("native-session forensic database disappeared while opening");
            }
            return Err(classify_forensic_inventory_read_error(
                "open retained native-session inventory read-only",
                error,
            ));
        }
    };
    drop(file);
    Ok(connection)
}

fn bounded_forensic_diagnostic(detail: impl std::fmt::Display) -> String {
    let mut detail = detail.to_string();
    if detail.len() > MAX_FORENSIC_DIAGNOSTIC_BYTES {
        let mut end = MAX_FORENSIC_DIAGNOSTIC_BYTES;
        while !detail.is_char_boundary(end) {
            end -= 1;
        }
        detail.truncate(end);
    }
    detail
}

fn forensic_source_error(
    nonce: Option<&str>,
    path: PathBuf,
    kind: NativeSessionForensicErrorKind,
    detail: impl std::fmt::Display,
) -> NativeSessionForensicSourceError {
    let session_nonce = nonce
        .filter(|value| value.len() <= 128 && uuid::Uuid::parse_str(value).is_ok())
        .map(str::to_owned);
    NativeSessionForensicSourceError {
        session_nonce,
        path,
        kind,
        detail: bounded_forensic_diagnostic(detail),
    }
}

#[cfg(test)]
fn read_forensic_projection(
    connection: &Connection,
    nonce: &str,
) -> Result<(SqliteValue, SqliteValue, bool)> {
    read_optional_forensic_projection(connection, nonce)?
        .context("native-session forensic nonce has no unique retained admission")
}

/// Keep the exact query shared by export and discovery. SQL bounds each JSON
/// value before it crosses into the product parser, even with a corrupt schema.
fn read_optional_forensic_projection(
    connection: &Connection,
    nonce: &str,
) -> Result<Option<(SqliteValue, SqliteValue, bool)>> {
    let rows = connection
        .query_with_params(
            "SELECT
            CASE WHEN typeof(admission_json) = 'text'
                  AND LENGTH(CAST(admission_json AS BLOB)) <= ?2
                 THEN admission_json ELSE NULL END,
            CASE WHEN typeof(outcome_json) = 'text'
                  AND LENGTH(CAST(outcome_json AS BLOB)) <= ?3
                 THEN outcome_json ELSE NULL END,
            CASE WHEN outcome_json IS NULL OR
                      (typeof(outcome_json) = 'text'
                       AND LENGTH(CAST(outcome_json AS BLOB)) <= ?3)
                 THEN 1 ELSE 0 END
         FROM native_sessions WHERE session_nonce = ?1 LIMIT 2;",
            &[
                SqliteValue::Text(nonce.to_owned().into()),
                SqliteValue::Integer(i64::try_from(MAX_ADMISSION_BYTES)?),
                SqliteValue::Integer(i64::try_from(MAX_OUTCOME_BYTES)?),
            ],
        )
        .map_err(|error| {
            classify_forensic_inventory_read_error(
                "read retained native-session inventory projection",
                error,
            )
        })?;
    if rows.is_empty() {
        return Ok(None);
    }
    let [row] = rows.as_slice() else {
        bail!("native-session forensic nonce has no unique retained admission");
    };
    let [admission, projected_outcome, outcome_within_bound] = row.values() else {
        bail!("native-session forensic inventory row shape is invalid");
    };
    Ok(Some((
        admission.clone(),
        projected_outcome.clone(),
        matches!(outcome_within_bound, SqliteValue::Integer(1)),
    )))
}

fn authenticate_forensic_admission(
    protected_root: &Path,
    nonce: &str,
    value: &SqliteValue,
    key: &ed25519_dalek::VerifyingKey,
) -> std::result::Result<
    (NativeSessionAdmission, NativeSessionAdmissionReceipt),
    NativeSessionForensicSourceError,
> {
    let admission = (|| -> Result<NativeSessionAdmission> {
        let admission: NativeSessionAdmission = parse_json(value, MAX_ADMISSION_BYTES)?;
        validate_admission(&admission)?;
        if admission.session_nonce != nonce {
            bail!("native-session forensic nonce does not match the retained admission");
        }
        Ok(admission)
    })()
    .map_err(|error| {
        forensic_source_error(
            Some(nonce),
            protected_root.join(INVENTORY_FILE),
            NativeSessionForensicErrorKind::AdmissionInvalid,
            format!("{error:#}"),
        )
    })?;
    let capture_directory = protected_root.join(RUNTIME_EVIDENCE_CAPTURE_DIR_RELATIVE_PATH);
    validate_existing_forensic_directory(&capture_directory)
        .and_then(|()| verify_admission_capture_with_root(protected_root, &admission, key))
        .map_err(|error| {
            forensic_source_error(
                Some(nonce),
                capture_directory,
                NativeSessionForensicErrorKind::IdentityInvalid,
                format!("{error:#}"),
            )
        })?;
    let receipt = read_admission_receipt(protected_root, &admission, key)
        .map_err(|error| {
            forensic_source_error(
                Some(nonce),
                admission_receipt_path(protected_root, nonce),
                NativeSessionForensicErrorKind::AdmissionReceiptInvalid,
                format!("{error:#}"),
            )
        })?
        .ok_or_else(|| {
            forensic_source_error(
                Some(nonce),
                admission_receipt_path(protected_root, nonce),
                NativeSessionForensicErrorKind::AdmissionReceiptMissing,
                "native-session forensic admission has no authenticated receipt",
            )
        })?;
    // Historical exact database rows remain usable without a retained body.
    // When both sources exist, neither a damaged object nor disagreement may
    // be hidden by choosing the more convenient source.
    let retained = read_retained_admission_record(protected_root, nonce, key).map_err(|error| {
        forensic_source_error(
            Some(nonce),
            admission_record_path(protected_root, nonce),
            NativeSessionForensicErrorKind::AdmissionRecordInvalid,
            format!("{error:#}"),
        )
    })?;
    if let Some((retained, _)) = retained
        && retained != admission
    {
        return Err(forensic_source_error(
            Some(nonce),
            admission_record_path(protected_root, nonce),
            NativeSessionForensicErrorKind::AdmissionRecordInvalid,
            "native-session database admission disagrees with its retained body",
        ));
    }
    Ok((admission, receipt))
}

fn authenticate_forensic_outcome(
    protected_root: &Path,
    admission: &NativeSessionAdmission,
    projected: &SqliteValue,
    within_bound: bool,
    key: &ed25519_dalek::VerifyingKey,
) -> std::result::Result<Option<NativeSessionOutcomeReceipt>, NativeSessionForensicSourceError> {
    let nonce = &admission.session_nonce;
    let projected_outcome = (|| -> Result<Option<NativeSessionOutcome>> {
        if !within_bound {
            bail!("native-session forensic outcome has invalid type or exceeds its byte bound");
        }
        match projected {
            SqliteValue::Null => Ok(None),
            value => {
                let outcome = parse_json(value, MAX_OUTCOME_BYTES)?;
                validate_outcome(admission, &outcome)?;
                Ok(Some(outcome))
            }
        }
    })()
    .map_err(|error| {
        forensic_source_error(
            Some(nonce),
            protected_root.join(INVENTORY_FILE),
            NativeSessionForensicErrorKind::OutcomeProjectionConflict,
            format!("{error:#}"),
        )
    })?;
    let receipt = read_outcome_receipt(protected_root, admission, key).map_err(|error| {
        forensic_source_error(
            Some(nonce),
            outcome_receipt_path(protected_root, nonce),
            NativeSessionForensicErrorKind::OutcomeReceiptInvalid,
            format!("{error:#}"),
        )
    })?;
    if let (Some(projected), Some(signed)) = (&projected_outcome, &receipt)
        && projected != &signed.outcome
    {
        return Err(forensic_source_error(
            Some(nonce),
            protected_root.join(INVENTORY_FILE),
            NativeSessionForensicErrorKind::OutcomeProjectionConflict,
            "native-session database outcome disagrees with its signed supervisor receipt",
        ));
    }
    Ok(receipt)
}

/// Read only an existing bounded journal. Absence never provisions a journal
/// or turns a pending launch into a zero-effect claim. Complete authentication
/// is performed by the independent SDK against the signed admission.
fn read_retained_native_session_effect_journal(
    protected_root: &Path,
    nonce: &str,
) -> Result<Option<String>> {
    use super::native_session_journal::{
        NATIVE_SESSION_EFFECT_JOURNAL_BYTE_CAP, NATIVE_SESSION_EFFECT_JOURNAL_DIRECTORY,
        native_session_effect_journal_path,
    };
    let directory = protected_root.join(NATIVE_SESSION_EFFECT_JOURNAL_DIRECTORY);
    match std::fs::symlink_metadata(&directory) {
        Ok(_) => validate_existing_forensic_directory(&directory)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).context("inspect retained native-session journal directory");
        }
    }
    let path = native_session_effect_journal_path(protected_root, nonce);
    if !validate_private_path_if_present(&path)? {
        return Ok(None);
    }
    let bytes = read_runtime_evidence_private_file(&path, NATIVE_SESSION_EFFECT_JOURNAL_BYTE_CAP)?;
    let jsonl = std::str::from_utf8(&bytes)
        .context("retained native-session journal is not UTF-8")?
        .to_owned();
    Ok(Some(jsonl))
}

fn make_native_session_forensic_bundle(
    admission: &NativeSessionAdmission,
    receipt: &NativeSessionAdmissionReceipt,
    outcome: Option<frankenengine_verifier_sdk::native_session::NativeSessionForensicOutcome>,
    journal_jsonl: Option<String>,
    source_capsule: Option<&[u8]>,
) -> Result<(
    frankenengine_verifier_sdk::native_session::NativeSessionForensicBundle,
    usize,
)> {
    use base64::Engine as _;
    use frankenengine_verifier_sdk::native_session::{
        MAX_NATIVE_SESSION_FORENSICS_BYTES, MAX_NATIVE_SESSION_FORENSICS_V2_BYTES,
        MAX_NATIVE_SESSION_FORENSICS_V3_BYTES, NATIVE_SESSION_FORENSICS_SCHEMA,
        NATIVE_SESSION_FORENSICS_V2_SCHEMA, NATIVE_SESSION_FORENSICS_V3_SCHEMA,
        NativeSessionForensicAdmissionReceipt, NativeSessionForensicBundle,
    };
    let (schema, byte_cap) = if source_capsule.is_some() {
        (
            NATIVE_SESSION_FORENSICS_V3_SCHEMA,
            MAX_NATIVE_SESSION_FORENSICS_V3_BYTES,
        )
    } else if journal_jsonl.is_some() {
        (
            NATIVE_SESSION_FORENSICS_V2_SCHEMA,
            MAX_NATIVE_SESSION_FORENSICS_V2_BYTES,
        )
    } else {
        (
            NATIVE_SESSION_FORENSICS_SCHEMA,
            MAX_NATIVE_SESSION_FORENSICS_BYTES,
        )
    };
    let bundle = NativeSessionForensicBundle {
        schema_version: schema.to_owned(),
        admission_json: bounded_json(admission, MAX_ADMISSION_BYTES)?,
        journal_jsonl,
        source_capsule_base64: source_capsule
            .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes)),
        admission_receipt: NativeSessionForensicAdmissionReceipt {
            schema_version: receipt.schema_version.clone(),
            session_nonce: receipt.session_nonce.clone(),
            product_root_key_id: receipt.product_root_key_id.clone(),
            admission_sha256: receipt.admission_sha256.clone(),
            signature_hex: receipt.signature_hex.clone(),
        },
        outcome,
    };
    Ok((bundle, byte_cap))
}

fn export_native_session_forensics_at(
    protected_root: &Path,
    nonce: &str,
) -> Result<NativeSessionForensicExport> {
    use frankenengine_verifier_sdk::native_session::{
        NativeSessionForensicOutcome, verify_native_session_forensics,
    };

    validate_forensic_session_nonce(nonce)?;
    for directory in [
        protected_root
            .parent()
            .context("native-session evidence has no product directory")?
            .to_path_buf(),
        protected_root.to_path_buf(),
        protected_root.join("keys"),
        protected_root.join(RUNTIME_EVIDENCE_CAPTURE_DIR_RELATIVE_PATH),
        protected_root.join(ADMISSION_RECEIPT_DIRECTORY),
    ] {
        validate_existing_forensic_directory(&directory)?;
    }
    let outcome_directory = protected_root.join(OUTCOME_RECEIPT_DIRECTORY);
    match std::fs::symlink_metadata(&outcome_directory) {
        Ok(_) => validate_existing_forensic_directory(&outcome_directory)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect retained native-session outcomes"),
    }
    let root = load_runtime_evidence_product_root(
        &protected_root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH),
    )?;
    let key = root.verifying_key();
    drop(root);
    let (projection, inventory_projection, inventory_diagnostic) =
        if !validate_forensic_inventory_paths(protected_root)? {
            (None, NativeSessionForensicProjection::MissingDatabase, None)
        } else {
            let projection = (|| -> Result<_> {
                let connection = open_forensic_inventory(protected_root)?;
                read_optional_forensic_projection(&connection, nonce)
            })();
            match projection {
                Ok(Some(values)) => (Some(values), NativeSessionForensicProjection::Matched, None),
                Ok(None) => (
                    None,
                    NativeSessionForensicProjection::MissingAdmission,
                    None,
                ),
                Err(error) => {
                    let Some(unavailable) =
                        error.downcast_ref::<NativeSessionForensicInventoryUnavailable>()
                    else {
                        return Err(error);
                    };
                    if !validate_forensic_inventory_paths(protected_root)? {
                        bail!("native-session forensic database disappeared while reading");
                    }
                    (
                        None,
                        NativeSessionForensicProjection::UnreadableDatabase,
                        Some(unavailable.detail.clone()),
                    )
                }
            }
        };
    let (admission, receipt, projected_outcome, outcome_within_bound) = match projection {
        Some((admission_value, projected_outcome, outcome_within_bound)) => {
            if !matches!(admission_value, SqliteValue::Text(_)) || !outcome_within_bound {
                bail!(
                    "native-session forensic inventory JSON column has invalid type or exceeds its byte bound"
                );
            }
            let (admission, receipt) =
                authenticate_forensic_admission(protected_root, nonce, &admission_value, &key)?;
            (admission, receipt, projected_outcome, outcome_within_bound)
        }
        None => {
            let (admission, receipt) = read_retained_admission_record(protected_root, nonce, &key)?
                .context(
                    "native-session forensic export requires a retained authenticated admission \
                     record when the inventory projection is unavailable",
                )?;
            // No projected outcome can be inferred from a lost row. Only the
            // independently authenticated original supervisor receipt may be
            // exported; its absence remains pending with unknown liveness.
            (admission, receipt, SqliteValue::Null, true)
        }
    };
    let outcome = authenticate_forensic_outcome(
        protected_root,
        &admission,
        &projected_outcome,
        outcome_within_bound,
        &key,
    )?;
    let journal_jsonl = read_retained_native_session_effect_journal(protected_root, nonce)?;
    let source_capsule = read_retained_native_session_source_capsule(protected_root, &admission)?;
    let (bundle, byte_cap) = make_native_session_forensic_bundle(
        &admission,
        &receipt,
        outcome
            .map(|receipt| -> Result<_> {
                Ok(NativeSessionForensicOutcome {
                    payload_json: receipt.payload_json()?,
                    signature_hex: receipt.signature_hex,
                })
            })
            .transpose()?,
        journal_jsonl,
        source_capsule.as_ref().map(|bytes| bytes.as_slice()),
    )?;
    let bytes = bounded_json(&bundle, byte_cap)?;
    let verification = verify_native_session_forensics(bytes.as_bytes(), &key)
        .map_err(|error| anyhow::anyhow!("native-session forensic export verification: {error}"))?;
    Ok(NativeSessionForensicExport {
        bundle,
        verification,
        inventory_projection,
        inventory_diagnostic,
    })
}

/// Authenticate the supervisor outcome of one independently selected launch.
///
/// The caller must retain the nonce and canonical project identities before
/// spawning the child; none may come from that child's stdout. Both immutable
/// receipts must verify against the existing protected product root. A retained
/// outcome can survive a missing database projection, but an unsigned database
/// row or a conflicting projection can never establish successful execution.
/// This preserves unknown effects and does not by itself authorize a restart.
pub fn authenticate_local_native_session_outcome(
    nonce: &str,
    expected_project: &Path,
    expected_entrypoint: &Path,
    expected_operator_project: &Path,
) -> Result<NativeSessionInventoryRecord> {
    let protected_root = existing_admission_root()?
        .context("authenticated native-session outcome requires an existing protected inventory")?;
    authenticate_native_session_outcome_at(
        &protected_root,
        nonce,
        expected_project,
        expected_entrypoint,
        expected_operator_project,
    )
}

fn authenticate_native_session_outcome_at(
    protected_root: &Path,
    nonce: &str,
    expected_project: &Path,
    expected_entrypoint: &Path,
    expected_operator_project: &Path,
) -> Result<NativeSessionInventoryRecord> {
    let parsed = uuid::Uuid::parse_str(nonce).context("invalid supervised native-session nonce")?;
    if parsed.to_string() != nonce || parsed.is_nil() {
        bail!("supervised native-session nonce must be a canonical non-nil UUID");
    }
    for path in [
        expected_project,
        expected_entrypoint,
        expected_operator_project,
    ] {
        project_key(path)?;
    }
    if expected_entrypoint == expected_project || !expected_entrypoint.starts_with(expected_project)
    {
        bail!("supervised native-session entrypoint must be inside its retained project");
    }
    // Reading an outcome must not provision authority or create missing state.
    for directory in [
        protected_root.to_path_buf(),
        protected_root.join("keys"),
        protected_root.join(RUNTIME_EVIDENCE_CAPTURE_DIR_RELATIVE_PATH),
        protected_root.join(ADMISSION_RECEIPT_DIRECTORY),
        protected_root.join(OUTCOME_RECEIPT_DIRECTORY),
    ] {
        std::fs::symlink_metadata(&directory)
            .context("authenticated native-session outcome is missing protected evidence")?;
        ensure_runtime_evidence_directory(&directory, true)?;
    }
    let connection = open_inventory(protected_root, false)?
        .context("authenticated native-session outcome has no retained admission database")?;
    let mut tx = connection.transaction()?;
    let rows = tx.query_with_params(
        "SELECT admission_json, outcome_json FROM native_sessions WHERE session_nonce = ?1;",
        &[SqliteValue::Text(nonce.to_owned().into())],
    )?;
    let [row] = rows.as_slice() else {
        bail!("supervised native-session nonce has no unique retained admission");
    };
    let [admission, projected_outcome] = row.values() else {
        bail!("supervised native-session inventory row shape is invalid");
    };
    let admission: NativeSessionAdmission = parse_json(admission, MAX_ADMISSION_BYTES)?;
    validate_admission(&admission)?;
    if admission.session_nonce != nonce
        || admission.project_root != expected_project
        || admission.entrypoint != expected_entrypoint
        || (expected_operator_project != expected_project
            && !admission.control_scopes.as_ref().is_some_and(|scopes| {
                scopes
                    .iter()
                    .any(|scope| scope.project_root == expected_operator_project)
            }))
    {
        bail!("native-session admission does not match the retained launch and control scope");
    }
    let projected_outcome: Option<NativeSessionOutcome> = match projected_outcome {
        SqliteValue::Null => None,
        value => Some(parse_json(value, MAX_OUTCOME_BYTES)?),
    };
    tx.commit()?;
    protect_sidecars(protected_root)?;
    verify_admission_capture(protected_root, &admission)?;
    let root = load_runtime_evidence_product_root(
        &protected_root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH),
    )?;
    let key = root.verifying_key();
    read_admission_receipt(protected_root, &admission, &key)?
        .context("supervised native-session admission has no authenticated receipt")?;
    let receipt = read_outcome_receipt(protected_root, &admission, &key)?
        .context("supervised native-session outcome has no authenticated receipt")?;
    if projected_outcome
        .as_ref()
        .is_some_and(|observed| observed != &receipt.outcome)
    {
        bail!("native-session database outcome disagrees with its signed supervisor receipt");
    }
    Ok(NativeSessionInventoryRecord {
        admission,
        outcome: Some(receipt.outcome),
    })
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
        let rows = read_records(&connection)?;
        drop(connection);
        protect_sidecars(protected_root)?;
        rows
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

pub const NATIVE_SESSION_INVENTORY_STATUS_SCHEMA: &str =
    "franken-node/ops-session-inventory-status/v1";
pub const NATIVE_SESSION_INVENTORY_COMPACT_SCHEMA: &str =
    "franken-node/ops-session-inventory-compact/v1";
pub const NATIVE_SESSION_COLD_ARCHIVE_SCHEMA: &str = "franken-node/native-session-cold-archive/v2";
const NATIVE_SESSION_COLD_ARCHIVE_V1_SCHEMA: &str = "franken-node/native-session-cold-archive/v1";
const COLD_ARCHIVE_DIRECTORY: &str = "session-cold-archives";
const MAX_RETAINED_COLD_ARCHIVES: usize = MAX_STORED_SESSIONS;
const MAX_RETAINED_COLD_ARCHIVE_SESSIONS: usize = MAX_IDENTITY_CAPTURES;
const MAX_RETAINED_COLD_ARCHIVE_BYTES: usize = MAX_RETAINED_ADMISSION_BYTES;
const MAX_COLD_ARCHIVE_BYTES: usize =
    frankenengine_verifier_sdk::native_session::MAX_NATIVE_SESSION_COLD_ARCHIVE_BYTES;
const NATIVE_SESSION_COLD_ARCHIVE_LEAF_DOMAIN: &[u8] =
    b"franken-node/native-session-cold-archive-leaf/v1\0";
const NATIVE_SESSION_COLD_ARCHIVE_V2_LEAF_DOMAIN: &[u8] =
    b"franken-node/native-session-cold-archive-leaf/v2\0";
const NATIVE_SESSION_COLD_ARCHIVE_NODE_DOMAIN: &[u8] =
    b"franken-node/native-session-cold-archive-node/v1\0";
const NATIVE_SESSION_COLD_ARCHIVE_SIG_DOMAIN: &[u8] =
    b"franken-node/native-session-cold-archive-sig/v1\0";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NativeSessionInventoryStatusReport {
    pub schema_version: String,
    pub inventory_root: PathBuf,
    pub database_present: bool,
    pub retained_sessions: usize,
    pub max_sessions: usize,
    pub pending_null_outcomes: usize,
    pub completed_sessions: usize,
    pub clean_completed_sessions: usize,
    pub incident_or_failed_sessions: usize,
    pub actual_payload_bytes: usize,
    pub pending_phantom_reserved_bytes: usize,
    pub reserved_bytes: usize,
    pub max_reserved_bytes: usize,
    pub utilization_pct: f64,
    pub admission_blocked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_command: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSessionInventoryCompactRequest {
    pub archive_dir: Option<PathBuf>,
    pub max_sessions_to_archive: Option<usize>,
    pub finalize_orphaned_pending: bool,
    pub min_pending_age_secs: u64,
    pub confirm: bool,
    pub operator_id: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSessionColdArchiveEntry {
    pub session_nonce: String,
    pub leaf_sha256: String,
    pub admission: NativeSessionAdmission,
    pub outcome: NativeSessionOutcome,
    /// The original product-signed engine identity is required by v2. Legacy
    /// v1 archives remain verifiable but cannot reconstruct a retired identity.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_cold_archive_identity"
    )]
    pub identity_capture: Option<RuntimeEvidenceIdentityCapture>,
}

fn deserialize_cold_archive_identity<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<RuntimeEvidenceIdentityCapture>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    RuntimeEvidenceIdentityCapture::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSessionColdArchiveBundle {
    pub schema_version: String,
    pub archived_at: DateTime<Utc>,
    pub operator_id: String,
    pub reason: String,
    pub session_count: usize,
    pub merkle_root_sha256: String,
    pub signing_public_key_hex: String,
    pub signature_hex: String,
    pub entries: Vec<NativeSessionColdArchiveEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NativeSessionInventoryCompactReport {
    pub schema_version: String,
    pub inventory_root: PathBuf,
    pub recovered_signed_outcomes: usize,
    pub finalized_orphaned_pending: usize,
    pub archived_clean_sessions: usize,
    /// Previously archived sessions whose interrupted hot-file retirement
    /// completed in this invocation; these are not newly archived DB rows.
    #[serde(default)]
    pub retired_archived_sessions: usize,
    /// Actual per-session files removed while resuming prior retirement.
    #[serde(default)]
    pub retired_archived_sidecars: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_merkle_root_sha256: Option<String>,
    pub before: NativeSessionInventoryStatusReport,
    pub after: NativeSessionInventoryStatusReport,
}

fn is_clean_completed_outcome(outcome: &NativeSessionOutcome) -> bool {
    outcome.kind == NativeSessionOutcomeKind::Completed
        && outcome.process == NativeSessionProcessObservation::WorkerReaped
        && outcome.panic_evidence.is_none()
        && matches!(
            outcome.effects,
            NativeSessionEffectObservation::FinalLedgerObserved {
                denied_count: 0,
                failed_count: 0,
                ..
            }
        )
}

fn cold_archive_leaf_sha256(
    admission: &NativeSessionAdmission,
    outcome: &NativeSessionOutcome,
    identity_capture: Option<&RuntimeEvidenceIdentityCapture>,
) -> Result<String> {
    let admission_bytes = bounded_json(admission, MAX_ADMISSION_BYTES)?;
    let outcome_bytes = bounded_json(outcome, MAX_OUTCOME_BYTES)?;
    let mut hash = Sha256::new();
    hash.update(if identity_capture.is_some() {
        NATIVE_SESSION_COLD_ARCHIVE_V2_LEAF_DOMAIN
    } else {
        NATIVE_SESSION_COLD_ARCHIVE_LEAF_DOMAIN
    });
    hash.update(u64::try_from(admission.session_nonce.len())?.to_be_bytes());
    hash.update(admission.session_nonce.as_bytes());
    hash.update(u64::try_from(admission_bytes.len())?.to_be_bytes());
    hash.update(admission_bytes.as_bytes());
    hash.update(u64::try_from(outcome_bytes.len())?.to_be_bytes());
    hash.update(outcome_bytes.as_bytes());
    if let Some(capture) = identity_capture {
        let capture_bytes = bounded_json(capture, 64 * 1024)?;
        hash.update(u64::try_from(capture_bytes.len())?.to_be_bytes());
        hash.update(capture_bytes.as_bytes());
    }
    Ok(hex::encode(hash.finalize()))
}

fn compute_cold_archive_merkle_root(leaves: &[String]) -> String {
    if leaves.is_empty() {
        let mut hash = Sha256::new();
        hash.update(NATIVE_SESSION_COLD_ARCHIVE_NODE_DOMAIN);
        hash.update(0_u64.to_be_bytes());
        return hex::encode(hash.finalize());
    }
    let mut level: Vec<String> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = &pair[0];
            let right = pair.get(1).unwrap_or(left);
            let mut hash = Sha256::new();
            hash.update(NATIVE_SESSION_COLD_ARCHIVE_NODE_DOMAIN);
            hash.update(left.as_bytes());
            hash.update(b":");
            hash.update(right.as_bytes());
            next.push(hex::encode(hash.finalize()));
        }
        level = next;
    }
    level.into_iter().next().unwrap_or_default()
}

fn cold_archive_signature_preimage(bundle: &NativeSessionColdArchiveBundle) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Signable<'a> {
        schema_version: &'a str,
        archived_at: &'a DateTime<Utc>,
        operator_id: &'a str,
        reason: &'a str,
        session_count: usize,
        merkle_root_sha256: &'a str,
        signing_public_key_hex: &'a str,
    }
    let payload = serde_json::to_vec(&Signable {
        schema_version: &bundle.schema_version,
        archived_at: &bundle.archived_at,
        operator_id: &bundle.operator_id,
        reason: &bundle.reason,
        session_count: bundle.session_count,
        merkle_root_sha256: &bundle.merkle_root_sha256,
        signing_public_key_hex: &bundle.signing_public_key_hex,
    })?;
    let mut preimage =
        Vec::with_capacity(NATIVE_SESSION_COLD_ARCHIVE_SIG_DOMAIN.len() + payload.len());
    preimage.extend_from_slice(NATIVE_SESSION_COLD_ARCHIVE_SIG_DOMAIN);
    preimage.extend_from_slice(&payload);
    Ok(preimage)
}

/// Independently verify every archived session leaf digest, the binary Merkle
/// root, and the strict Ed25519 signature over the archive metadata.
pub fn verify_native_session_cold_archive(
    bundle: &NativeSessionColdArchiveBundle,
    expected_verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<()> {
    if bundle.schema_version != NATIVE_SESSION_COLD_ARCHIVE_SCHEMA
        && bundle.schema_version != NATIVE_SESSION_COLD_ARCHIVE_V1_SCHEMA
    {
        bail!("unsupported native-session cold archive schema version");
    }
    if bundle.operator_id.trim().is_empty() || bundle.reason.trim().is_empty() {
        bail!("native-session cold archive requires non-empty operator_id and reason");
    }
    if bundle.session_count != bundle.entries.len()
        || bundle.entries.is_empty()
        || bundle.entries.len() > MAX_STORED_SESSIONS
    {
        bail!("native-session cold archive session_count does not match entries");
    }
    let expected_key_hex = hex::encode(expected_verifying_key.as_bytes());
    if !crate::security::constant_time::ct_eq(&bundle.signing_public_key_hex, &expected_key_hex) {
        bail!("native-session cold archive signing key does not match trusted product root");
    }
    let mut leaves = Vec::with_capacity(bundle.entries.len());
    let mut seen = BTreeSet::new();
    for entry in &bundle.entries {
        if entry.session_nonce != entry.admission.session_nonce
            || !seen.insert(entry.session_nonce.clone())
        {
            bail!("native-session cold archive contains duplicate or mismatched session nonce");
        }
        validate_admission(&entry.admission)?;
        validate_outcome(&entry.admission, &entry.outcome)?;
        if !is_clean_completed_outcome(&entry.outcome) {
            bail!("native-session cold archive contains non-clean session outcome");
        }
        let capture = match (&*bundle.schema_version, &entry.identity_capture) {
            (NATIVE_SESSION_COLD_ARCHIVE_SCHEMA, Some(capture)) => {
                verify_capture_for_admission(&entry.admission, capture, expected_verifying_key)?;
                Some(capture)
            }
            (NATIVE_SESSION_COLD_ARCHIVE_V1_SCHEMA, None) => None,
            _ => bail!("native-session cold archive identity does not match its schema version"),
        };
        let recomputed_leaf = cold_archive_leaf_sha256(&entry.admission, &entry.outcome, capture)?;
        if !crate::security::constant_time::ct_eq(&entry.leaf_sha256, &recomputed_leaf) {
            bail!(
                "native-session cold archive leaf digest mismatch for {}",
                entry.session_nonce
            );
        }
        leaves.push(recomputed_leaf);
    }
    let recomputed_root = compute_cold_archive_merkle_root(&leaves);
    if !crate::security::constant_time::ct_eq(&bundle.merkle_root_sha256, &recomputed_root) {
        bail!("native-session cold archive Merkle root mismatch");
    }
    if bundle.signature_hex.len() != 128 {
        bail!("native-session cold archive signature has invalid length");
    }
    let sig_bytes = hex::decode(&bundle.signature_hex)
        .context("decode native-session cold archive signature")?;
    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .context("parse native-session cold archive signature")?;
    expected_verifying_key
        .verify_strict(&cold_archive_signature_preimage(bundle)?, &signature)
        .context("native-session cold archive Ed25519 signature verification failed")?;
    Ok(())
}

#[derive(Default)]
struct RetainedColdArchiveEvidence {
    entries: BTreeMap<String, (PathBuf, NativeSessionColdArchiveEntry)>,
    archived_sessions: usize,
}

fn retained_cold_archive_path(protected_root: &Path, bytes: &[u8]) -> PathBuf {
    protected_root
        .join(COLD_ARCHIVE_DIRECTORY)
        .join(format!("{}.json", hex::encode(Sha256::digest(bytes))))
}

/// Cold evidence belongs to forensic discovery only. It must never re-enter
/// the hot admission, lease, drain, or effect-accounting population.
fn read_retained_cold_archives(
    protected_root: &Path,
    key: &ed25519_dalek::VerifyingKey,
) -> Result<RetainedColdArchiveEvidence> {
    let directory = protected_root.join(COLD_ARCHIVE_DIRECTORY);
    match std::fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RetainedColdArchiveEvidence::default());
        }
        Err(error) => return Err(error).context("inspect retained native-session cold archives"),
        Ok(_) => validate_existing_forensic_directory(&directory)?,
    }
    let mut paths = std::fs::read_dir(&directory)?
        .take(MAX_RETAINED_COLD_ARCHIVES + 1)
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    if paths.len() > MAX_RETAINED_COLD_ARCHIVES {
        bail!("retained native-session cold archives exceed their file bound");
    }
    paths.sort();
    let mut evidence = RetainedColdArchiveEvidence::default();
    let mut retained_bytes = 0usize;
    let mut capture_owners = BTreeMap::new();
    let capture_directory = protected_root.join(RUNTIME_EVIDENCE_CAPTURE_DIR_RELATIVE_PATH);
    for path in paths {
        let bytes = read_runtime_evidence_private_file(&path, MAX_COLD_ARCHIVE_BYTES)?;
        retained_bytes = retained_bytes.saturating_add(bytes.len());
        if retained_bytes > MAX_RETAINED_COLD_ARCHIVE_BYTES {
            bail!("retained native-session cold archives exceed their aggregate byte bound");
        }
        if path != retained_cold_archive_path(protected_root, &bytes) {
            bail!("retained native-session cold archive does not match its content address");
        }
        let bundle: NativeSessionColdArchiveBundle = serde_json::from_slice(&bytes)
            .context("decode retained native-session cold archive")?;
        verify_native_session_cold_archive(&bundle, key)?;
        if bundle.schema_version != NATIVE_SESSION_COLD_ARCHIVE_SCHEMA {
            bail!(
                "legacy native-session cold archive has no retained engine identities; forensic coverage is incomplete"
            );
        }
        evidence.archived_sessions = evidence
            .archived_sessions
            .saturating_add(bundle.entries.len());
        if evidence.archived_sessions > MAX_RETAINED_COLD_ARCHIVE_SESSIONS {
            bail!("retained native-session cold archives exceed their session bound");
        }
        for entry in bundle.entries {
            if entry.admission.identity_capture_path.parent() != Some(capture_directory.as_path()) {
                bail!("archived native-session capture is outside its protected capture directory");
            }
            if let Some(owner) = capture_owners.insert(
                entry.admission.identity_capture_path.clone(),
                entry.session_nonce.clone(),
            ) && owner != entry.session_nonce
            {
                bail!("retained native-session cold archives disagree on capture ownership");
            }
            match evidence.entries.get(&entry.session_nonce) {
                Some((_, previous)) if previous != &entry => {
                    bail!(
                        "retained native-session cold archives contain conflicting session evidence"
                    );
                }
                Some(_) => {}
                None => {
                    evidence
                        .entries
                        .insert(entry.session_nonce.clone(), (path.clone(), entry));
                }
            }
        }
    }
    Ok(evidence)
}

/// Restore the exact public identity retained before hot-evidence retirement.
/// The caller must first establish that the original capture is absent; an
/// archive must never conceal an invalid or contradictory present capture.
pub(crate) fn load_archived_runtime_evidence_identity(
    protected_root: &Path,
    capture_path: &Path,
) -> Result<Option<RuntimeEvidenceIdentityCapture>> {
    if let Some(product_root) = protected_root.parent() {
        validate_existing_forensic_directory(product_root)?;
    }
    validate_existing_forensic_directory(protected_root)?;
    validate_existing_forensic_directory(&protected_root.join("keys"))?;
    let capture_directory = protected_root.join(RUNTIME_EVIDENCE_CAPTURE_DIR_RELATIVE_PATH);
    validate_existing_forensic_directory(&capture_directory)?;
    if capture_path.parent() != Some(capture_directory.as_path()) {
        bail!("archived runtime evidence capture is outside its protected capture directory");
    }
    let root = load_runtime_evidence_product_root(
        &protected_root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH),
    )?;
    let key = root.verifying_key();
    drop(root);
    let evidence = read_retained_cold_archives(protected_root, &key)?;
    Ok(evidence
        .entries
        .into_values()
        .find(|(_, entry)| entry.admission.identity_capture_path == capture_path)
        .and_then(|(_, entry)| entry.identity_capture))
}

fn sync_retained_cold_archive(protected_root: &Path, path: &Path) -> Result<()> {
    let archive_directory = protected_root.join(COLD_ARCHIVE_DIRECTORY);
    if path.parent() != Some(archive_directory.as_path()) {
        bail!("native-session cold archive durability path is outside protected retention");
    }
    #[cfg(unix)]
    let file = {
        use rustix::fs::{Mode, OFlags, open};
        std::fs::File::from(open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?)
    };
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt as _;
        // FlushFileBuffers requires a writable handle. Opening the reparse
        // point itself preserves the same metadata refusal as private reads.
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(0x0020_0000)
            .share_mode(0x0000_0003)
            .open(path)?
    };
    #[cfg(not(any(unix, windows)))]
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;
    validate_runtime_evidence_private_file_metadata(path, &file.metadata()?)?;
    file.sync_all()
        .context("sync retained native-session cold archive")?;
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, open};
        // The archive directory may itself be newly created. Persist both
        // namespace entries before hot retirement, including retries that
        // encounter a file published before an earlier directory-sync error.
        for directory in [archive_directory, protected_root.to_path_buf()] {
            let file = std::fs::File::from(open(
                &directory,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            file.sync_all()
                .context("sync native-session cold archive directory")?;
        }
    }
    Ok(())
}

fn retain_cold_archive(
    protected_root: &Path,
    bytes: &[u8],
    bundle: &NativeSessionColdArchiveBundle,
    key: &ed25519_dalek::VerifyingKey,
) -> Result<PathBuf> {
    use std::io::Write as _;

    if bytes.len() > MAX_COLD_ARCHIVE_BYTES
        || bundle.schema_version != NATIVE_SESSION_COLD_ARCHIVE_SCHEMA
    {
        bail!("retaining a native-session cold archive requires bounded v2 identity evidence");
    }
    verify_native_session_cold_archive(bundle, key)?;
    let decoded: NativeSessionColdArchiveBundle = serde_json::from_slice(bytes)?;
    if &decoded != bundle {
        bail!("native-session cold archive bytes disagree with the verified bundle");
    }
    let directory = protected_root.join(COLD_ARCHIVE_DIRECTORY);
    ensure_runtime_evidence_directory(&directory, true)?;
    let existing = read_retained_cold_archives(protected_root, key)?;
    let path = retained_cold_archive_path(protected_root, bytes);
    if validate_private_path_if_present(&path)? {
        if read_runtime_evidence_private_file(&path, MAX_COLD_ARCHIVE_BYTES)?.as_slice() != bytes {
            bail!("retained native-session cold archive content-address collision");
        }
        sync_retained_cold_archive(protected_root, &path)?;
        return Ok(path);
    }
    if existing
        .archived_sessions
        .saturating_add(bundle.entries.len())
        > MAX_RETAINED_COLD_ARCHIVE_SESSIONS
    {
        bail!("retained native-session cold archives exceed their session bound");
    }
    let capture_owners: BTreeMap<_, _> = existing
        .entries
        .values()
        .map(|(_, entry)| (&entry.admission.identity_capture_path, &entry.session_nonce))
        .collect();
    for entry in &bundle.entries {
        if let Some((_, previous)) = existing.entries.get(&entry.session_nonce)
            && previous != entry
        {
            bail!("new native-session cold archive conflicts with retained session evidence");
        }
        if let Some(owner) = capture_owners.get(&entry.admission.identity_capture_path)
            && **owner != entry.session_nonce
        {
            bail!("new native-session cold archive conflicts with retained capture ownership");
        }
    }
    check_private_directory_capacity(
        &directory,
        1,
        bytes.len(),
        MAX_RETAINED_COLD_ARCHIVES,
        MAX_RETAINED_COLD_ARCHIVE_BYTES,
        "cold archive",
        "cold archives",
    )?;
    // Stage outside the discovery directory so readers never mistake a
    // partially written temporary file for an authenticated archive.
    let mut staged = tempfile::NamedTempFile::new_in(protected_root)
        .context("stage retained native-session cold archive")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        staged
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    staged.write_all(bytes)?;
    staged.as_file().sync_all()?;
    staged
        .persist_noclobber(&path)
        .map_err(|error| error.error)
        .context("persist retained native-session cold archive")?;
    let retained = read_runtime_evidence_private_file(&path, MAX_COLD_ARCHIVE_BYTES)?;
    if retained.as_slice() != bytes {
        bail!("retained native-session cold archive changed before hot-evidence retirement");
    }
    let verified: NativeSessionColdArchiveBundle = serde_json::from_slice(&retained)?;
    verify_native_session_cold_archive(&verified, key)?;
    if &verified != bundle {
        bail!("retained native-session cold archive differs from the authenticated observation");
    }
    sync_retained_cold_archive(protected_root, &path)?;
    Ok(path)
}

fn inspect_status_in_tx(
    protected_root: &Path,
    tx: &Transaction<'_>,
) -> Result<NativeSessionInventoryStatusReport> {
    let (count, reserved_bytes) = inventory_reservation_usage(tx)?;
    let rows = tx.query(&format!(
        "SELECT session_nonce, admission_json, outcome_json FROM native_sessions
         ORDER BY session_nonce ASC LIMIT {};",
        MAX_STORED_SESSIONS.saturating_add(1)
    ))?;
    let mut pending_null_outcomes = 0_usize;
    let mut completed_sessions = 0_usize;
    let mut clean_completed_sessions = 0_usize;
    let mut incident_or_failed_sessions = 0_usize;
    let mut actual_payload_bytes = 0_usize;
    for row in &rows {
        let [_, admission_val, outcome_val] = row.values() else {
            bail!("native-session inventory row shape is invalid");
        };
        if let SqliteValue::Text(adm) = admission_val {
            actual_payload_bytes = actual_payload_bytes.saturating_add(adm.len());
        }
        match outcome_val {
            SqliteValue::Null => {
                pending_null_outcomes = pending_null_outcomes.saturating_add(1);
            }
            SqliteValue::Text(out_raw) => {
                completed_sessions = completed_sessions.saturating_add(1);
                actual_payload_bytes = actual_payload_bytes.saturating_add(out_raw.len());
                match serde_json::from_str::<NativeSessionOutcome>(out_raw) {
                    Ok(outcome) if is_clean_completed_outcome(&outcome) => {
                        clean_completed_sessions = clean_completed_sessions.saturating_add(1);
                    }
                    _ => {
                        incident_or_failed_sessions = incident_or_failed_sessions.saturating_add(1);
                    }
                }
            }
            _ => bail!("native-session inventory contains a non-text outcome column"),
        }
    }
    let pending_phantom_reserved_bytes = pending_null_outcomes.saturating_mul(MAX_OUTCOME_BYTES);
    let session_pct = (count as f64 / MAX_STORED_SESSIONS as f64) * 100.0;
    let byte_pct = (reserved_bytes as f64 / MAX_RESERVED_BYTES as f64) * 100.0;
    let utilization_pct = (session_pct.max(byte_pct) * 100.0).round() / 100.0;
    let admission_blocked = count >= MAX_STORED_SESSIONS
        || reserved_bytes.saturating_add(MAX_OUTCOME_BYTES) > MAX_RESERVED_BYTES;
    let fix_command = if admission_blocked || utilization_pct >= 85.0 {
        if pending_phantom_reserved_bytes > actual_payload_bytes && pending_null_outcomes > 0 {
            Some(
                "franken-node ops session-inventory compact --finalize-orphaned-pending \
                 --confirm --operator-id <operator> --reason 'reclaim orphaned killed-worker reservations' --json"
                    .to_string(),
            )
        } else {
            Some(
                "franken-node ops session-inventory compact --archive-dir <archive-dir> \
                 --operator-id <operator> --reason 'archive clean completed sessions' --json"
                    .to_string(),
            )
        }
    } else {
        None
    };
    Ok(NativeSessionInventoryStatusReport {
        schema_version: NATIVE_SESSION_INVENTORY_STATUS_SCHEMA.to_string(),
        inventory_root: protected_root.to_path_buf(),
        database_present: true,
        retained_sessions: count,
        max_sessions: MAX_STORED_SESSIONS,
        pending_null_outcomes,
        completed_sessions,
        clean_completed_sessions,
        incident_or_failed_sessions,
        actual_payload_bytes,
        pending_phantom_reserved_bytes,
        reserved_bytes,
        max_reserved_bytes: MAX_RESERVED_BYTES,
        utilization_pct,
        admission_blocked,
        fix_command,
    })
}

/// Read-only inspection of native-session inventory utilization and capacity.
/// Never mutates the database and succeeds even when admission capacity is
/// currently saturated so operators can diagnose and unbrick a host cleanly.
pub fn inspect_native_session_inventory_status_at(
    protected_root: &Path,
) -> Result<NativeSessionInventoryStatusReport> {
    if !protected_root.join(INVENTORY_FILE).exists() {
        return Ok(NativeSessionInventoryStatusReport {
            schema_version: NATIVE_SESSION_INVENTORY_STATUS_SCHEMA.to_string(),
            inventory_root: protected_root.to_path_buf(),
            database_present: false,
            retained_sessions: 0,
            max_sessions: MAX_STORED_SESSIONS,
            pending_null_outcomes: 0,
            completed_sessions: 0,
            clean_completed_sessions: 0,
            incident_or_failed_sessions: 0,
            actual_payload_bytes: 0,
            pending_phantom_reserved_bytes: 0,
            reserved_bytes: 0,
            max_reserved_bytes: MAX_RESERVED_BYTES,
            utilization_pct: 0.0,
            admission_blocked: false,
            fix_command: None,
        });
    }
    retry_snapshot_conflict(|| {
        let Some(connection) = open_capacity_inventory_at(protected_root, true)? else {
            return Ok(NativeSessionInventoryStatusReport {
                schema_version: NATIVE_SESSION_INVENTORY_STATUS_SCHEMA.to_string(),
                inventory_root: protected_root.to_path_buf(),
                database_present: false,
                retained_sessions: 0,
                max_sessions: MAX_STORED_SESSIONS,
                pending_null_outcomes: 0,
                completed_sessions: 0,
                clean_completed_sessions: 0,
                incident_or_failed_sessions: 0,
                actual_payload_bytes: 0,
                pending_phantom_reserved_bytes: 0,
                reserved_bytes: 0,
                max_reserved_bytes: MAX_RESERVED_BYTES,
                utilization_pct: 0.0,
                admission_blocked: false,
                fix_command: None,
            });
        };
        let tx = connection.transaction()?;
        inspect_status_in_tx(protected_root, &tx)
    })
}

fn archived_session_sidecar_paths(
    protected_root: &Path,
    nonce: &str,
    capture_path: &Path,
) -> Result<[PathBuf; 6]> {
    let capture_directory = protected_root.join(RUNTIME_EVIDENCE_CAPTURE_DIR_RELATIVE_PATH);
    if capture_path.parent() != Some(capture_directory.as_path()) {
        bail!("archived session retirement capture is outside its protected directory");
    }
    Ok([
        admission_record_path(protected_root, nonce),
        admission_receipt_path(protected_root, nonce),
        outcome_receipt_path(protected_root, nonce),
        supervisor_lease::path(protected_root, nonce),
        super::native_session_journal::native_session_effect_journal_path(protected_root, nonce),
        capture_path.to_path_buf(),
    ])
}

fn archive_retirement_directories(protected_root: &Path) -> Result<Vec<PathBuf>> {
    if let Some(product_root) = protected_root.parent() {
        validate_existing_forensic_directory(product_root)?;
    }
    validate_existing_forensic_directory(protected_root)?;
    let mut directories = Vec::new();
    for name in [
        ADMISSION_RECORD_DIRECTORY,
        ADMISSION_RECEIPT_DIRECTORY,
        OUTCOME_RECEIPT_DIRECTORY,
        supervisor_lease::DIRECTORY,
        super::native_session_journal::NATIVE_SESSION_EFFECT_JOURNAL_DIRECTORY,
        RUNTIME_EVIDENCE_CAPTURE_DIR_RELATIVE_PATH,
    ] {
        let directory = protected_root.join(name);
        match std::fs::symlink_metadata(&directory) {
            Ok(_) => {
                validate_existing_forensic_directory(&directory)?;
                directories.push(directory);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).context("inspect archived session retirement directory");
            }
        }
    }
    Ok(directories)
}

fn sync_archive_retirement_directories(directories: &[PathBuf]) -> Result<()> {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, open};

        // Sync all evidence directories, including ones whose last file was
        // removed by an earlier failed attempt. Only syncing this attempt's
        // unlinks would leave that previous retirement barrier unfinished.
        for directory in directories {
            validate_existing_forensic_directory(directory)?;
            let file = std::fs::File::from(open(
                directory,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            file.sync_all()
                .context("sync archived session retirement directory")?;
        }
    }
    #[cfg(not(unix))]
    let _ = directories;
    Ok(())
}

fn finish_archive_retirement<T>(
    directories: &[PathBuf],
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let result = operation();
    let durability = sync_archive_retirement_directories(directories);
    match (result, durability) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(sync_error)) => Err(error.context(format!(
            "archived sidecar retirement also failed its durability barrier: {sync_error:#}"
        ))),
    }
}

fn retire_archived_session_sidecars(
    protected_root: &Path,
    nonce: &str,
    capture_path: &Path,
    surviving_captures: &BTreeSet<PathBuf>,
) -> Result<usize> {
    let mut removed = 0;
    for path in archived_session_sidecar_paths(protected_root, nonce, capture_path)? {
        if path.as_path() == capture_path && surviving_captures.contains(capture_path) {
            continue;
        }
        let directory = path
            .parent()
            .context("archived session sidecar has no parent")?;
        match std::fs::symlink_metadata(directory) {
            Ok(_) => validate_existing_forensic_directory(directory)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("inspect archived session sidecar parent"),
        }
        if validate_private_path_if_present(&path)? {
            match std::fs::remove_file(&path) {
                Ok(()) => removed += 1,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("retire archived native-session sidecar {}", path.display())
                    });
                }
            }
        }
    }
    Ok(removed)
}

enum ArchiveRetirementLease {
    Retain,
    Retire(Option<supervisor_lease::SupervisorLease>),
}

fn probe_archive_retirement_lease(
    protected_root: &Path,
    admission: &NativeSessionAdmission,
    key: &ed25519_dalek::VerifyingKey,
) -> Result<ArchiveRetirementLease> {
    let admission_sha256 = admission_digest(admission)?;
    match supervisor_lease::probe(
        protected_root,
        &supervisor_lease::Binding {
            session_nonce: &admission.session_nonce,
            product_root_key_id: &admission.product_root_key_id,
            admission_sha256: &admission_sha256,
        },
        key,
    )? {
        supervisor_lease::Probe::Live => Ok(ArchiveRetirementLease::Retain),
        supervisor_lease::Probe::Orphaned(lease) => Ok(ArchiveRetirementLease::Retire(Some(lease))),
        supervisor_lease::Probe::Unproven => {
            // Partial retirement may already have removed the marker. An
            // existing marker on an unsupported platform remains unproven;
            // absence never substitutes for a terminal outcome or archive.
            if validate_private_path_if_present(&supervisor_lease::path(
                protected_root,
                &admission.session_nonce,
            ))? {
                Ok(ArchiveRetirementLease::Retain)
            } else {
                Ok(ArchiveRetirementLease::Retire(None))
            }
        }
    }
}

#[derive(Default)]
struct ArchivedSidecarRetirement {
    sessions: usize,
    sidecars: usize,
}

/// Resume a previous compaction while holding the inventory writer lock.
/// A readable absent row and a verified protected archive authorize only
/// retirement of matching per-session files, never a new outcome or lease.
fn resume_archived_sidecar_retirement(
    protected_root: &Path,
    records: &[NativeSessionInventoryRecord],
    protected_sessions: &BTreeSet<String>,
    key: &ed25519_dalek::VerifyingKey,
    max_sessions: usize,
) -> Result<ArchivedSidecarRetirement> {
    if max_sessions == 0 {
        return Ok(ArchivedSidecarRetirement::default());
    }
    let archived = read_retained_cold_archives(protected_root, key)?;
    if archived.entries.is_empty() {
        return Ok(ArchivedSidecarRetirement::default());
    }
    let directories = archive_retirement_directories(protected_root)?;
    let admitted: BTreeSet<&str> = records
        .iter()
        .map(|record| record.admission.session_nonce.as_str())
        .collect();
    let surviving_captures: BTreeSet<PathBuf> = records
        .iter()
        .map(|record| record.admission.identity_capture_path.clone())
        .collect();
    let mut candidates = Vec::new();
    let mut inspected_bytes = 0usize;
    for (nonce, (archive_path, entry)) in &archived.entries {
        if candidates.len() >= max_sessions {
            break;
        }
        if admitted.contains(nonce.as_str()) || protected_sessions.contains(nonce) {
            continue;
        }
        let mut residue_present = false;
        for path in archived_session_sidecar_paths(
            protected_root,
            nonce,
            &entry.admission.identity_capture_path,
        )? {
            residue_present |= validate_private_path_if_present(&path)?;
        }
        if !residue_present {
            continue;
        }
        if surviving_captures.contains(&entry.admission.identity_capture_path) {
            bail!("archived session retirement conflicts with an admitted identity capture");
        }
        let ArchiveRetirementLease::Retire(_lease) =
            probe_archive_retirement_lease(protected_root, &entry.admission, key)?
        else {
            continue;
        };
        validate_archived_hot_residue(protected_root, key, entry, &mut inspected_bytes)?;
        candidates.push((archive_path, entry));
    }
    // Validate the entire selected batch before removing any evidence. Keep
    // every selected cold source durable, even after an earlier failed sync.
    let mut synced_archives = BTreeSet::new();
    for (archive_path, _) in &candidates {
        if synced_archives.insert(*archive_path) {
            sync_retained_cold_archive(protected_root, archive_path)?;
        }
    }
    finish_archive_retirement(&directories, || {
        let mut retired = ArchivedSidecarRetirement::default();
        let mut inspected_bytes = 0usize;
        for (_, entry) in candidates {
            // Reacquire just one owner at a time to bound open descriptors.
            // Hold it through unlinking; a newly live owner remains untouched.
            let ArchiveRetirementLease::Retire(_lease) =
                probe_archive_retirement_lease(protected_root, &entry.admission, key)?
            else {
                continue;
            };
            validate_archived_hot_residue(protected_root, key, entry, &mut inspected_bytes)?;
            let removed = retire_archived_session_sidecars(
                protected_root,
                &entry.session_nonce,
                &entry.admission.identity_capture_path,
                &surviving_captures,
            )?;
            if removed > 0 {
                retired.sessions += 1;
                retired.sidecars += removed;
            }
        }
        Ok(retired)
    })
}

fn validate_cold_archive_export_directory(protected_root: &Path, directory: &Path) -> Result<()> {
    fn prospective_canonical_path(path: &Path) -> Result<PathBuf> {
        let absolute = std::path::absolute(path)?;
        let mut ancestor = absolute.as_path();
        let mut missing = Vec::new();
        loop {
            match ancestor.canonicalize() {
                Ok(mut resolved) => {
                    for component in missing.into_iter().rev() {
                        resolved.push(component);
                    }
                    return Ok(resolved);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    missing.push(
                        ancestor
                            .file_name()
                            .context("archive directory has an unresolved noncanonical ancestor")?
                            .to_os_string(),
                    );
                    ancestor = ancestor
                        .parent()
                        .context("archive directory has no resolvable parent")?;
                }
                Err(error) => {
                    return Err(error).context("resolve native-session archive directory");
                }
            }
        }
    }

    let retained = prospective_canonical_path(protected_root)?.join(COLD_ARCHIVE_DIRECTORY);
    if prospective_canonical_path(directory)?.starts_with(&retained) {
        bail!("operator archive export directory overlaps protected native-session cold retention");
    }
    Ok(())
}

/// Compact native-session inventory capacity without silently discarding
/// incident, failed, panicked, denied-effect, or active session evidence:
/// 1. Recovers any already-signed `session-outcomes/` receipts.
/// 2. When `finalize_orphaned_pending` + `confirm` are explicitly requested by
///    an operator, seals aged `outcome_json IS NULL` rows only after acquiring
///    their authenticated supervisor ownership lease. Live, missing-lease and
///    unresolved-drain sessions remain retained. Eligible orphans receive signed
///    `SupervisionIncomplete` + `Unproven` + `Unknown` outcomes (preserving
///    unresolved-effect alarms while releasing ~5.35 MiB phantom reservations).
/// 3. When `archive_dir` is supplied, seals authenticated clean completed exit-0
///    non-incident sessions into an Ed25519-signed Merkle cold-archive bundle,
///    verifies the persisted bundle from disk, and atomically removes only those
///    verified clean rows from `native_sessions`. Previously archived sessions
///    whose rows are already absent resume exact hot-sidecar retirement first,
///    sharing the requested session bound with newly archived sessions.
pub fn compact_native_session_inventory_at(
    protected_root: &Path,
    request: &NativeSessionInventoryCompactRequest,
) -> Result<NativeSessionInventoryCompactReport> {
    use ed25519_dalek::Signer as _;
    use std::io::Write as _;

    if request.archive_dir.is_none() && !request.finalize_orphaned_pending {
        bail!(
            "session-inventory compact requires --archive-dir <dir> and/or \
             --finalize-orphaned-pending --confirm"
        );
    }
    let operator_id = request
        .operator_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .context("session-inventory compact requires a non-empty --operator-id")?
        .to_string();
    let reason = request
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .context("session-inventory compact requires a non-empty --reason")?
        .to_string();
    if request.finalize_orphaned_pending && !request.confirm {
        bail!(
            "refusing to finalize orphaned pending sessions without explicit --confirm; \
             finalization records honest SupervisionIncomplete/Unknown outcomes and never \
             marks orphaned sessions as cleanly completed"
        );
    }
    if let Some(directory) = &request.archive_dir {
        // Check missing destinations through their nearest existing ancestor
        // before creating directories or publishing any operator-named file.
        validate_cold_archive_export_directory(protected_root, directory)?;
    }

    let before = inspect_native_session_inventory_status_at(protected_root)?;
    if !before.database_present {
        return Ok(NativeSessionInventoryCompactReport {
            schema_version: NATIVE_SESSION_INVENTORY_COMPACT_SCHEMA.to_string(),
            inventory_root: protected_root.to_path_buf(),
            recovered_signed_outcomes: 0,
            finalized_orphaned_pending: 0,
            archived_clean_sessions: 0,
            retired_archived_sessions: 0,
            retired_archived_sidecars: 0,
            archive_path: None,
            archive_merkle_root_sha256: None,
            after: before.clone(),
            before,
        });
    }

    tracing::info!(
        event_code = "NSI_COMPACT_START",
        retained_sessions = before.retained_sessions,
        pending_null_outcomes = before.pending_null_outcomes,
        reserved_bytes = before.reserved_bytes,
        finalize_orphaned_pending = request.finalize_orphaned_pending,
        archive_requested = request.archive_dir.is_some(),
        operator_id = %operator_id,
        "starting native-session inventory compaction"
    );

    let root_key = load_runtime_evidence_product_root(
        &protected_root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH),
    )?;
    let verifying_key = root_key.verifying_key();
    let _write_lock = lock_inventory_file(protected_root, false)?;
    let protected_sessions = retry_snapshot_conflict(|| {
        let connection = open_inventory_unlocked(protected_root, false)?
            .context("native-session inventory disappeared before compaction census")?;
        let tx = connection.transaction()?;
        compaction_protected_sessions(&tx, &verifying_key)
    })?;

    let mut recovered_signed_outcomes = 0_usize;
    let mut finalized_orphaned_pending = 0_usize;
    let mut archived_clean_sessions = 0_usize;
    let mut retired_archived_sessions = 0_usize;
    let mut retired_archived_sidecars = 0_usize;
    let mut archive_path_out: Option<PathBuf> = None;
    let mut archive_merkle_root_out: Option<String> = None;

    // Phase 1: Opportunistically recover any already-signed outcome receipts.
    let pending_snapshot = retry_snapshot_conflict(|| {
        let connection = open_inventory_unlocked(protected_root, false)?
            .context("native-session inventory disappeared during compaction")?;
        let tx = connection.transaction()?;
        read_records_in_transaction_matching(&tx, true)
    })?;
    let recoveries = retained_outcome_recoveries(protected_root, &pending_snapshot)?;
    if !recoveries.is_empty() {
        retry_snapshot_conflict(|| {
            let connection = open_inventory_unlocked(protected_root, false)?
                .context("native-session inventory disappeared during recovery")?;
            let mut tx = connection.transaction()?;
            for (admission, outcome) in &recoveries {
                write_observed_outcome(&mut tx, admission, outcome)?;
            }
            tx.commit()?;
            protect_sidecars(protected_root)?;
            Ok(())
        })?;
        recovered_signed_outcomes = recoveries.len();
    }

    // Phase 2: Explicit operator finalization of aged orphaned pending rows.
    if request.finalize_orphaned_pending {
        let now = Utc::now();
        let remaining_pending = retry_snapshot_conflict(|| {
            let connection = open_inventory_unlocked(protected_root, false)?
                .context("native-session inventory disappeared before pending finalization")?;
            let tx = connection.transaction()?;
            read_records_in_transaction_matching(&tx, true)
        })?;
        let mut to_finalize = Vec::new();
        let mut retained_live = 0_usize;
        let mut retained_unproven = 0_usize;
        let mut retained_for_drain = 0_usize;
        for record in remaining_pending {
            let old_enough = now
                .signed_duration_since(record.admission.admitted_at)
                .to_std()
                .is_ok_and(|age| age.as_secs() >= request.min_pending_age_secs);
            if !old_enough {
                continue;
            }
            if protected_sessions.contains(&record.admission.session_nonce) {
                retained_for_drain += 1;
                continue;
            }
            let Some(receipt) =
                read_admission_receipt(protected_root, &record.admission, &verifying_key)?
            else {
                retained_unproven += 1;
                continue;
            };
            let lease = match supervisor_lease::probe(
                protected_root,
                &supervisor_lease::Binding {
                    session_nonce: &record.admission.session_nonce,
                    product_root_key_id: &record.admission.product_root_key_id,
                    admission_sha256: &receipt.admission_sha256,
                },
                &verifying_key,
            )? {
                supervisor_lease::Probe::Live => {
                    retained_live += 1;
                    continue;
                }
                supervisor_lease::Probe::Unproven => {
                    retained_unproven += 1;
                    continue;
                }
                supervisor_lease::Probe::Orphaned(lease) => lease,
            };
            // A supervisor can publish its real receipt and die after phase
            // one's snapshot. Recover that exact observation before considering
            // an operator's weaker unknown outcome.
            let retained = read_outcome_receipt(protected_root, &record.admission, &verifying_key)?;
            let recovered = retained.is_some();
            let outcome = match retained {
                Some(receipt) => receipt.outcome,
                None => NativeSessionOutcome {
                    observed_at: now,
                    kind: NativeSessionOutcomeKind::SupervisionIncomplete,
                    process: NativeSessionProcessObservation::Unproven,
                    containment_empty_observed: false,
                    effects: NativeSessionEffectObservation::Unknown,
                    panic_evidence: None,
                },
            };
            validate_outcome(&record.admission, &outcome)?;
            if !recovered {
                retain_outcome_receipt(protected_root, &record.admission, &outcome)?;
            }
            // Keep every acquired descriptor until the projection commit;
            // timestamp or PID state never substitutes for this ownership.
            to_finalize.push((record.admission, outcome, lease, recovered));
        }
        if !to_finalize.is_empty() {
            retry_snapshot_conflict(|| {
                let connection = open_inventory_unlocked(protected_root, false)?
                    .context("native-session inventory disappeared during pending finalization")?;
                let mut tx = connection.transaction()?;
                for (admission, outcome, _lease, _recovered) in &to_finalize {
                    write_observed_outcome(&mut tx, admission, outcome)?;
                }
                tx.commit()?;
                protect_sidecars(protected_root)?;
                Ok(())
            })?;
            let recovered_after_snapshot = to_finalize
                .iter()
                .filter(|(_, _, _, recovered)| *recovered)
                .count();
            recovered_signed_outcomes += recovered_after_snapshot;
            finalized_orphaned_pending = to_finalize.len() - recovered_after_snapshot;
            tracing::info!(
                event_code = "NSI_PENDING_FINALIZED",
                finalized_orphaned_pending,
                operator_id = %operator_id,
                "sealed orphaned pending native sessions with honest SupervisionIncomplete/Unknown outcomes"
            );
        }
        if retained_live + retained_unproven + retained_for_drain > 0 {
            tracing::info!(
                event_code = "NSI_PENDING_RETAINED",
                retained_live,
                retained_unproven,
                retained_for_drain,
                "preserved live, ownership-unproven and fleet-owned pending sessions"
            );
        }
    }

    // Phase 3: Signed Merkle cold-archive compaction of authenticated clean completed sessions only.
    if let Some(archive_dir) = &request.archive_dir {
        if let Ok(meta) = std::fs::symlink_metadata(archive_dir)
            && meta.file_type().is_symlink()
        {
            bail!(
                "refusing to write native-session cold archive into symlinked directory {}",
                archive_dir.display()
            );
        }
        std::fs::create_dir_all(archive_dir).with_context(|| {
            format!(
                "create native-session cold archive directory {}",
                archive_dir.display()
            )
        })?;
        validate_cold_archive_export_directory(protected_root, archive_dir)?;
        let all_records = retry_snapshot_conflict(|| {
            let connection = open_inventory_unlocked(protected_root, false)?
                .context("native-session inventory disappeared before cold-archive scan")?;
            let tx = connection.transaction()?;
            read_records_in_transaction_matching(&tx, false)
        })?;
        // Fail closed if any retained DB outcome disagrees with its signed
        // supervisor receipt, and never archive/delete unproven rows.
        let authority = authenticate_inventory_records(protected_root, &all_records)?;
        let max_archive = request.max_sessions_to_archive.unwrap_or(usize::MAX);
        let retired = resume_archived_sidecar_retirement(
            protected_root,
            &all_records,
            &protected_sessions,
            &verifying_key,
            max_archive,
        )?;
        retired_archived_sessions = retired.sessions;
        retired_archived_sidecars = retired.sidecars;
        let max_archive = max_archive.saturating_sub(retired_archived_sessions);
        let mut entries = Vec::new();
        let mut leaves = Vec::new();
        for record in all_records {
            if entries.len() >= max_archive {
                break;
            }
            if protected_sessions.contains(&record.admission.session_nonce) {
                continue;
            }
            if authority
                .unproven_admissions
                .contains(&record.admission.session_nonce)
                || authority
                    .unproven_outcomes
                    .contains(&record.admission.session_nonce)
            {
                continue;
            }
            let Some(outcome) = record.outcome else {
                continue;
            };
            if !is_clean_completed_outcome(&outcome) {
                continue;
            }
            let admission_sha256 = admission_digest(&record.admission)?;
            match supervisor_lease::probe(
                protected_root,
                &supervisor_lease::Binding {
                    session_nonce: &record.admission.session_nonce,
                    product_root_key_id: &record.admission.product_root_key_id,
                    admission_sha256: &admission_sha256,
                },
                &verifying_key,
            )? {
                // Phase one may have recovered a real receipt while its live
                // supervisor is still waiting to finish the database update.
                supervisor_lease::Probe::Live => continue,
                // Admission cannot reacquire this immutable marker, and the
                // writer lock excludes another admission or compaction. Avoid
                // retaining a descriptor for every archived row.
                supervisor_lease::Probe::Orphaned(lease) => drop(lease),
                // Original authenticated clean outcomes remain archivable for
                // historical admissions; no synthetic outcome is inferred here.
                supervisor_lease::Probe::Unproven => {}
            }
            let capture_bytes = read_runtime_evidence_private_file(
                &record.admission.identity_capture_path,
                64 * 1024,
            )?;
            let capture: RuntimeEvidenceIdentityCapture = serde_json::from_slice(&capture_bytes)
                .context("decode native-session identity before cold archiving")?;
            verify_capture_for_admission(&record.admission, &capture, &verifying_key)?;
            let leaf_sha256 =
                cold_archive_leaf_sha256(&record.admission, &outcome, Some(&capture))?;
            leaves.push(leaf_sha256.clone());
            entries.push(NativeSessionColdArchiveEntry {
                session_nonce: record.admission.session_nonce.clone(),
                leaf_sha256,
                admission: record.admission,
                outcome,
                identity_capture: Some(capture),
            });
        }
        if !entries.is_empty() {
            let merkle_root_sha256 = compute_cold_archive_merkle_root(&leaves);
            let archived_at = Utc::now();
            let mut bundle = NativeSessionColdArchiveBundle {
                schema_version: NATIVE_SESSION_COLD_ARCHIVE_SCHEMA.to_string(),
                archived_at,
                operator_id: operator_id.clone(),
                reason: reason.clone(),
                session_count: entries.len(),
                merkle_root_sha256: merkle_root_sha256.clone(),
                signing_public_key_hex: hex::encode(verifying_key.as_bytes()),
                signature_hex: String::new(),
                entries,
            };
            let preimage = cold_archive_signature_preimage(&bundle)?;
            bundle.signature_hex = hex::encode(root_key.sign(&preimage).to_bytes());
            verify_native_session_cold_archive(&bundle, &verifying_key)?;

            let encoded = serde_json::to_vec_pretty(&bundle)
                .context("serialize native-session cold archive bundle")?;
            if encoded.len() > MAX_COLD_ARCHIVE_BYTES {
                bail!("native-session cold archive exceeds its retained byte bound");
            }
            let file_name = format!(
                "native-session-archive-{}-{}.json",
                archived_at.format("%Y%m%dT%H%M%SZ"),
                &merkle_root_sha256[..16.min(merkle_root_sha256.len())]
            );
            let final_path = archive_dir.join(file_name);
            let mut staged = tempfile::NamedTempFile::new_in(archive_dir)
                .context("stage native-session cold archive bundle")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                staged
                    .as_file()
                    .set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            staged.write_all(&encoded)?;
            staged.as_file().sync_all()?;
            staged
                .persist_noclobber(&final_path)
                .map_err(|err| err.error)
                .with_context(|| {
                    format!(
                        "persist native-session cold archive bundle to {}",
                        final_path.display()
                    )
                })?;
            #[cfg(unix)]
            std::fs::File::open(archive_dir)?.sync_all()?;

            // Re-read and independently verify the persisted archive before deleting any DB rows.
            let persisted_bytes =
                read_runtime_evidence_private_file(&final_path, MAX_COLD_ARCHIVE_BYTES)
                    .with_context(|| {
                        format!(
                            "read back persisted native-session cold archive {}",
                            final_path.display()
                        )
                    })?;
            let verified_bundle: NativeSessionColdArchiveBundle =
                serde_json::from_slice(&persisted_bytes)
                    .context("decode persisted native-session cold archive for verification")?;
            verify_native_session_cold_archive(&verified_bundle, &verifying_key)?;
            if verified_bundle != bundle {
                bail!(
                    "persisted native-session cold archive changed before hot-evidence retirement"
                );
            }
            // The operator's export directory may disappear or be moved. Keep
            // a bounded, content-addressed copy in protected runtime evidence,
            // durably published and reverified before removing any hot input.
            retain_cold_archive(
                protected_root,
                &persisted_bytes,
                &verified_bundle,
                &verifying_key,
            )?;

            let archived_sessions: Vec<(String, PathBuf)> = verified_bundle
                .entries
                .iter()
                .map(|entry| {
                    (
                        entry.session_nonce.clone(),
                        entry.admission.identity_capture_path.clone(),
                    )
                })
                .collect();
            let retirement_directories = archive_retirement_directories(protected_root)?;
            let surviving_captures: BTreeSet<PathBuf> = retry_snapshot_conflict(|| {
                let connection = open_inventory_unlocked(protected_root, false)?
                    .context("native-session inventory disappeared before row deletion")?;
                let mut tx = connection.transaction()?;
                for (nonce, _) in &archived_sessions {
                    tx.execute_with_params(
                        "DELETE FROM native_sessions
                         WHERE session_nonce = ?1 AND outcome_json IS NOT NULL;",
                        &[SqliteValue::Text(nonce.clone().into())],
                    )?;
                }
                let remaining = read_records_in_transaction_matching(&tx, false)?;
                tx.commit()?;
                protect_sidecars(protected_root)?;
                Ok(remaining
                    .into_iter()
                    .map(|record| record.admission.identity_capture_path)
                    .collect())
            })?;

            // New and interrupted retirements share the same bounded private
            // paths and directory durability barrier. Shared source capsules
            // are never removed, and surviving admissions keep their captures.
            finish_archive_retirement(&retirement_directories, || {
                for (nonce, capture_path) in &archived_sessions {
                    retire_archived_session_sidecars(
                        protected_root,
                        nonce,
                        capture_path,
                        &surviving_captures,
                    )?;
                }
                Ok(())
            })?;

            archived_clean_sessions = archived_sessions.len();
            archive_path_out = Some(final_path);
            archive_merkle_root_out = Some(merkle_root_sha256);
            tracing::info!(
                event_code = "NSI_ARCHIVE_SIGNED",
                archived_clean_sessions,
                merkle_root = ?archive_merkle_root_out,
                "verified signed Merkle cold archive and reclaimed clean completed session rows"
            );
        }
    }

    let after = retry_snapshot_conflict(|| {
        let connection = open_inventory_unlocked(protected_root, false)?
            .context("native-session inventory disappeared after compaction")?;
        let tx = connection.transaction()?;
        inspect_status_in_tx(protected_root, &tx)
    })?;
    drop(_write_lock);
    tracing::info!(
        event_code = "NSI_COMPACT_COMPLETE",
        recovered_signed_outcomes,
        finalized_orphaned_pending,
        archived_clean_sessions,
        retired_archived_sessions,
        retired_archived_sidecars,
        before_reserved_bytes = before.reserved_bytes,
        after_reserved_bytes = after.reserved_bytes,
        "completed native-session inventory compaction"
    );

    Ok(NativeSessionInventoryCompactReport {
        schema_version: NATIVE_SESSION_INVENTORY_COMPACT_SCHEMA.to_string(),
        inventory_root: protected_root.to_path_buf(),
        recovered_signed_outcomes,
        finalized_orphaned_pending,
        archived_clean_sessions,
        retired_archived_sessions,
        retired_archived_sidecars,
        archive_path: archive_path_out,
        archive_merkle_root_sha256: archive_merkle_root_out,
        before,
        after,
    })
}

pub fn compact_local_native_session_inventory(
    request: &NativeSessionInventoryCompactRequest,
) -> Result<NativeSessionInventoryCompactReport> {
    compact_native_session_inventory_at(&inventory_root()?, request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frankenengine_engine::{
        evidence_ledger::RuntimeEvidenceAuthority, security_epoch::SecurityEpoch,
        signature_preimage::SigningKey,
    };

    fn fixture(root: &Path, marker: u8) -> NativeSessionAdmission {
        // The fixture's parent represents the private product directory, not
        // a user's general state-home directory. Model its provisioned mode.
        ensure_runtime_evidence_directory(root.parent().unwrap(), true).unwrap();
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
            source_capsule: None,
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
    fn effect_journal_preparation_requires_retained_authority_before_worker_start() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 142);
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        let receipt = admission_receipt_path(&root, &admission.session_nonce);
        let retained_receipt = receipt.with_extension("retained");
        std::fs::rename(&receipt, &retained_receipt).unwrap();
        assert!(guard.prepare_effect_journal().is_err());
        assert!(
            !root
                .join(super::super::native_session_journal::NATIVE_SESSION_EFFECT_JOURNAL_DIRECTORY)
                .exists()
        );
        std::fs::rename(&retained_receipt, &receipt).unwrap();
        let journal = guard.prepare_effect_journal().unwrap();
        let journal_path = super::super::native_session_journal::native_session_effect_journal_path(
            &root,
            &admission.session_nonce,
        );
        let header = std::fs::read(&journal_path).unwrap();
        assert!(!header.is_empty());
        assert!(guard.prepare_effect_journal().is_err());
        guard.worker_started();
        assert!(
            guard
                .prepare_effect_journal()
                .unwrap_err()
                .to_string()
                .contains("before worker spawn")
        );
        drop(journal);
        assert_eq!(std::fs::read(journal_path).unwrap(), header);
        // The test observes no worker exit or terminal effect outcome.
        guard.finished = true;
    }

    fn forensic_interruption(
        admission: &NativeSessionAdmission,
    ) -> NativeEffectInterruptionEvidence {
        NativeEffectInterruptionEvidence {
            schema_version: NATIVE_EFFECT_INTERRUPTION_EVIDENCE_SCHEMA.to_owned(),
            session_nonce: admission.session_nonce.clone(),
            terminal_state: "worker_exit_indeterminate".to_owned(),
            replay_certified: false,
            journal_complete: true,
            journal_event_cap: NATIVE_SESSION_MAX_EFFECT_WAL_EVENTS,
            completed_effect_count: 1,
            interrupted_effect_count: 1,
            entries: vec![
                NativeEffectWalEntry {
                    sequence: 0,
                    effect_kind: "fs_write".to_owned(),
                    request_hash: format!("sha256:{}", "ab".repeat(32)),
                    state: NativeEffectWalState::ProviderReturned,
                },
                NativeEffectWalEntry {
                    sequence: 1,
                    effect_kind: "network_request".to_owned(),
                    request_hash: format!("sha256:{}", "cd".repeat(32)),
                    state: NativeEffectWalState::InterruptedIndeterminate,
                },
            ],
            protocol_error: None,
            control_trigger: None,
        }
    }

    fn forensic_state_snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn visit(root: &Path, current: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in std::fs::read_dir(current).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    files.insert(path.strip_prefix(root).unwrap().to_path_buf(), Vec::new());
                    visit(root, &path, files);
                } else {
                    files.insert(
                        path.strip_prefix(root).unwrap().to_path_buf(),
                        std::fs::read(path).unwrap(),
                    );
                }
            }
        }
        let mut files = BTreeMap::new();
        visit(root, root, &mut files);
        files
    }

    fn retire_forensic_inventory(root: &Path, destination: &Path) {
        std::fs::create_dir(destination).unwrap();
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let name = format!("{INVENTORY_FILE}{suffix}");
            let path = root.join(&name);
            if path.try_exists().unwrap() {
                std::fs::rename(path, destination.join(name)).unwrap();
            }
        }
    }

    #[test]
    fn admission_record_is_retained_and_authenticated_before_worker_start() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 160);
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        let path = admission_record_path(&root, &admission.session_nonce);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            serde_json::to_vec(&admission).unwrap()
        );
        let key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]).verifying_key();
        let (retained, receipt) =
            read_retained_admission_record(&root, &admission.session_nonce, &key)
                .unwrap()
                .unwrap();
        assert_eq!(retained, admission);
        receipt.verify(&retained, &key).unwrap();
        let export = export_native_session_forensics_at(&root, &admission.session_nonce).unwrap();
        assert_eq!(
            export.inventory_projection,
            NativeSessionForensicProjection::Matched
        );
        assert!(export.inventory_diagnostic.is_none());
        assert_eq!(export.verification.outcome_kind, "pending");
        assert!(!export.verification.quiescence_certified);
        assert!(!export.verification.historical_completeness);
        // Retention is not a worker-start or completion observation.
        guard.finished = true;
    }

    #[test]
    fn admission_record_retention_reuses_exact_bytes_and_bounds_orphaned_files() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 161);
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        guard.finished = true;
        drop(guard);
        let _write_lock = lock_inventory_file(&root, true).unwrap();
        let before = forensic_state_snapshot(&root);
        retain_admission_record(&root, &admission).unwrap();
        assert_eq!(forensic_state_snapshot(&root), before);
        let directory = root.join(ADMISSION_RECORD_DIRECTORY);
        let path = admission_record_path(&root, &admission.session_nonce);
        let bytes = std::fs::read(&path).unwrap();
        assert!(check_admission_record_capacity(&directory, 0, 0, 1, bytes.len()).is_ok());
        assert!(check_admission_record_capacity(&directory, 1, 0, 1, bytes.len()).is_err());
        assert!(check_admission_record_capacity(&directory, 0, 1, 1, bytes.len()).is_err());
        create_new_runtime_evidence_private_file(&directory.join("orphaned-publication"), b"{")
            .unwrap();
        assert!(check_admission_record_capacity(&directory, 0, 0, 1, bytes.len() + 1).is_err());
        assert!(check_admission_record_capacity(&directory, 0, 0, 2, bytes.len()).is_err());
        assert!(check_admission_record_capacity(&directory, 0, 0, 2, bytes.len() + 1).is_ok());
        let mut changed = admission.clone();
        changed
            .dependency_ids
            .push("different-dependency".to_owned());
        assert!(retain_admission_record(&root, &changed).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        // Incomplete evidence is retained for diagnosis and never repaired.
        std::fs::write(&path, b"{").unwrap();
        assert!(retain_admission_record(&root, &admission).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"{");
    }

    #[test]
    fn forensic_export_accepts_legacy_admission_record_absence_without_backfilling() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 162);
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        guard.finished = true;
        drop(guard);
        let directory = root.join(ADMISSION_RECORD_DIRECTORY);
        std::fs::rename(&directory, temp.path().join("retained-admissions")).unwrap();
        let before = forensic_state_snapshot(&root);
        let export = export_native_session_forensics_at(&root, &admission.session_nonce).unwrap();
        assert_eq!(
            export.bundle.admission_json,
            serde_json::to_string(&admission).unwrap()
        );
        assert_eq!(export.verification.outcome_kind, "pending");
        assert!(!directory.exists());
        assert_eq!(forensic_state_snapshot(&root), before);
    }

    #[test]
    fn forensic_export_refuses_invalid_admission_records_without_repair() {
        for mutation in 0..5 {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let admission = fixture(&root, 163);
            let mut guard =
                NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            guard.finished = true;
            drop(guard);
            let path = admission_record_path(&root, &admission.session_nonce);
            let bytes = match mutation {
                0 => {
                    let mut changed = admission.clone();
                    changed
                        .dependency_ids
                        .push("unsigned-dependency".to_owned());
                    serde_json::to_vec(&changed).unwrap()
                }
                1 => format!("{}\n", serde_json::to_string(&admission).unwrap()).into_bytes(),
                2 => b"{".to_vec(),
                3 => vec![b'x'; MAX_ADMISSION_BYTES + 1],
                4 => {
                    let mut changed = admission.clone();
                    changed.session_nonce = uuid::Uuid::now_v7().to_string();
                    serde_json::to_vec(&changed).unwrap()
                }
                _ => unreachable!(),
            };
            std::fs::write(&path, bytes).unwrap();
            let before = forensic_state_snapshot(&root);
            assert!(
                export_native_session_forensics_at(&root, &admission.session_nonce).is_err(),
                "mutation {mutation}"
            );
            let discovery = read_native_session_forensics_at(&root, None).unwrap();
            assert!(discovery.records.is_empty());
            assert!(discovery.source_errors.iter().any(|error| {
                error.kind == NativeSessionForensicErrorKind::AdmissionRecordInvalid
            }));
            assert_eq!(forensic_state_snapshot(&root), before);
        }
    }

    #[cfg(unix)]
    #[test]
    fn forensic_admission_record_reads_refuse_unsafe_paths_and_permissions() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        for mutation in 0..3 {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let admission = fixture(&root, 164);
            let mut guard =
                NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            guard.finished = true;
            drop(guard);
            let directory = root.join(ADMISSION_RECORD_DIRECTORY);
            let path = admission_record_path(&root, &admission.session_nonce);
            match mutation {
                0 => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap()
                }
                1 => {
                    let retained = temp.path().join("retained-admission.json");
                    std::fs::rename(&path, &retained).unwrap();
                    symlink(&retained, &path).unwrap();
                }
                2 => std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))
                    .unwrap(),
                _ => unreachable!(),
            }
            let before = forensic_state_snapshot(&root);
            assert!(export_native_session_forensics_at(&root, &admission.session_nonce).is_err());
            assert_eq!(forensic_state_snapshot(&root), before);
            if mutation == 0 {
                assert_eq!(
                    std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o644
                );
            }
            if mutation == 2 {
                assert_eq!(
                    std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                    0o755
                );
            }
        }
    }

    #[test]
    fn forensic_export_recovers_retained_admissions_without_repairing_unavailable_inventory() {
        for with_outcome in [false, true] {
            for fault in 0..4 {
                let temp = tempfile::tempdir().unwrap();
                let root = temp.path().join("evidence");
                let admission = fixture(&root, 165);
                let mut guard =
                    NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
                if with_outcome {
                    abandon_after_receipt(&root, guard, &terminal_outcome());
                } else {
                    guard.finished = true;
                    drop(guard);
                }
                let expected_projection = match fault {
                    0 | 2 => {
                        retire_forensic_inventory(&root, &temp.path().join("retired-inventory"));
                        if fault == 2 {
                            create_new_runtime_evidence_private_file(
                                &root.join(INVENTORY_FILE),
                                &[b'x'; 4096],
                            )
                            .unwrap();
                            NativeSessionForensicProjection::UnreadableDatabase
                        } else {
                            NativeSessionForensicProjection::MissingDatabase
                        }
                    }
                    1 | 3 => {
                        let connection = open_inventory(&root, false).unwrap().unwrap();
                        let mut tx = connection.transaction().unwrap();
                        tx.execute(
                            "ALTER TABLE native_sessions RENAME TO retained_native_sessions;",
                        )
                        .unwrap();
                        if fault == 1 {
                            tx.execute("CREATE TABLE native_sessions (session_nonce TEXT NOT NULL, admission_json TEXT NOT NULL, outcome_json TEXT);")
                                .unwrap();
                        }
                        tx.commit().unwrap();
                        drop(tx);
                        drop(connection);
                        protect_sidecars(&root).unwrap();
                        if fault == 1 {
                            NativeSessionForensicProjection::MissingAdmission
                        } else {
                            NativeSessionForensicProjection::UnreadableDatabase
                        }
                    }
                    _ => unreachable!(),
                };
                let before = forensic_state_snapshot(&root);
                let export = export_native_session_forensics_at(&root, &admission.session_nonce)
                    .unwrap_or_else(|error| {
                        panic!("fault {fault}, signed outcome {with_outcome}: {error:#}")
                    });
                assert_eq!(export.inventory_projection, expected_projection);
                assert_eq!(
                    export.inventory_diagnostic.is_some(),
                    expected_projection == NativeSessionForensicProjection::UnreadableDatabase
                );
                if let Some(diagnostic) = &export.inventory_diagnostic {
                    assert!(!diagnostic.is_empty());
                    assert!(diagnostic.len() <= MAX_FORENSIC_DIAGNOSTIC_BYTES);
                }
                assert_eq!(
                    export.bundle.admission_json,
                    serde_json::to_string(&admission).unwrap()
                );
                assert_eq!(export.bundle.outcome.is_some(), with_outcome);
                assert_eq!(
                    export.verification.outcome_kind,
                    if with_outcome {
                        "control_stopped"
                    } else {
                        "pending"
                    }
                );
                assert!(!export.verification.replay_certified);
                assert!(!export.verification.quiescence_certified);
                assert!(!export.verification.historical_completeness);
                assert_eq!(forensic_state_snapshot(&root), before);
                if fault == 0 {
                    assert!(!root.join(INVENTORY_FILE).exists());
                }
            }
        }
    }

    #[test]
    fn forensic_export_fallback_requires_complete_original_admission_authority() {
        for mutation in 0..5 {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let admission = fixture(&root, 166);
            let guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            abandon_after_receipt(&root, guard, &terminal_outcome());
            retire_forensic_inventory(&root, &temp.path().join("retired-inventory"));
            let path = admission_record_path(&root, &admission.session_nonce);
            match mutation {
                0 => std::fs::rename(&path, temp.path().join("retained-admission.json")).unwrap(),
                1 => std::fs::write(&path, b"{").unwrap(),
                2 => {
                    let mut changed = admission.clone();
                    changed
                        .dependency_ids
                        .push("unsigned-dependency".to_owned());
                    std::fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
                }
                3 => std::fs::rename(
                    admission_receipt_path(&root, &admission.session_nonce),
                    temp.path().join("retained-receipt.json"),
                )
                .unwrap(),
                4 => std::fs::rename(
                    &admission.identity_capture_path,
                    temp.path().join("retained-identity.json"),
                )
                .unwrap(),
                _ => unreachable!(),
            }
            let before = forensic_state_snapshot(&root);
            assert!(
                export_native_session_forensics_at(&root, &admission.session_nonce).is_err(),
                "mutation {mutation}"
            );
            assert_eq!(forensic_state_snapshot(&root), before);
            assert!(!root.join(INVENTORY_FILE).exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn forensic_export_fallback_refuses_unsafe_inventory_and_orphaned_sidecars() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        for mutation in 0..4 {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let admission = fixture(&root, 167);
            let mut guard =
                NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            guard.finished = true;
            drop(guard);
            let retired = temp.path().join("retired-inventory");
            retire_forensic_inventory(&root, &retired);
            let database = root.join(INVENTORY_FILE);
            match mutation {
                0 => {
                    create_new_runtime_evidence_private_file(&database, &[b'x'; 4096]).unwrap();
                    std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o644))
                        .unwrap();
                }
                1 => symlink(retired.join(INVENTORY_FILE), &database).unwrap(),
                2 => symlink(
                    retired.join(INVENTORY_FILE),
                    root.join(format!("{INVENTORY_FILE}-wal")),
                )
                .unwrap(),
                3 => std::fs::hard_link(retired.join(INVENTORY_FILE), &database).unwrap(),
                _ => unreachable!(),
            }
            let before = forensic_state_snapshot(&root);
            assert!(
                export_native_session_forensics_at(&root, &admission.session_nonce).is_err(),
                "mutation {mutation}"
            );
            assert_eq!(forensic_state_snapshot(&root), before);
            if mutation == 0 {
                assert_eq!(
                    std::fs::metadata(&database).unwrap().permissions().mode() & 0o777,
                    0o644
                );
            }
        }
    }

    #[test]
    fn forensic_inventory_fallback_keeps_identity_access_and_limit_failures_fatal() {
        use fsqlite::FrankenError;

        for error in [
            FrankenError::CannotOpen {
                path: PathBuf::from("replaced.db"),
            },
            FrankenError::DatabaseNotFound {
                path: PathBuf::from("disappeared.db"),
            },
            FrankenError::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            FrankenError::AuthDenied,
            FrankenError::TooBig,
            FrankenError::QueryReturnedMultipleRows,
            FrankenError::Internal("unclassified failure".to_owned()),
        ] {
            let classified = classify_forensic_inventory_read_error("test read", error);
            assert!(
                classified
                    .downcast_ref::<NativeSessionForensicInventoryUnavailable>()
                    .is_none(),
                "{classified:#}"
            );
        }
        let classified = classify_forensic_inventory_read_error(
            "test read",
            FrankenError::DatabaseCorrupt {
                detail: "☃".repeat(MAX_FORENSIC_DIAGNOSTIC_BYTES),
            },
        );
        let unavailable = classified
            .downcast_ref::<NativeSessionForensicInventoryUnavailable>()
            .unwrap();
        assert!(unavailable.detail.starts_with("test read: "));
        assert!(unavailable.detail.len() <= MAX_FORENSIC_DIAGNOSTIC_BYTES);
    }

    #[cfg(unix)]
    #[test]
    fn forensic_export_recovers_original_sources_and_effect_journal_after_inventory_loss() {
        use base64::Engine as _;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let (admission, original_sources) = frozen_source_fixture(&root, 168);
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        let mut journal = guard.prepare_effect_journal().unwrap();
        let request_hash = format!("sha256:{}", "ef".repeat(32));
        journal.admit(0, "fs_write", &request_hash).unwrap();
        journal.complete(0).unwrap();
        journal.admit(1, "network_request", &request_hash).unwrap();
        drop(journal);
        guard.finished = true;
        drop(guard);
        let original_journal =
            read_retained_native_session_effect_journal(&root, &admission.session_nonce)
                .unwrap()
                .unwrap();
        retire_forensic_inventory(&root, &temp.path().join("retired-inventory"));
        std::fs::rename(&admission.project_root, temp.path().join("retired-source")).unwrap();
        let before = forensic_state_snapshot(&root);
        let export = export_native_session_forensics_at(&root, &admission.session_nonce).unwrap();
        assert_eq!(
            export.inventory_projection,
            NativeSessionForensicProjection::MissingDatabase
        );
        assert_eq!(
            export.bundle.schema_version,
            "franken-node/native-session-forensics/v3"
        );
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(export.bundle.source_capsule_base64.as_ref().unwrap())
                .unwrap(),
            original_sources
        );
        assert_eq!(
            export.bundle.journal_jsonl.as_ref(),
            Some(&original_journal)
        );
        assert!(export.bundle.outcome.is_none());
        assert_eq!(export.verification.outcome_kind, "pending");
        let journal = export.verification.durable_journal.as_ref().unwrap();
        assert_eq!(journal.admitted_provider_calls, 2);
        assert_eq!(journal.returned_provider_calls, 1);
        assert_eq!(journal.indeterminate_provider_calls, 1);
        assert!(!export.verification.replay_certified);
        assert!(!export.verification.quiescence_certified);
        assert!(!export.verification.historical_completeness);
        assert_eq!(forensic_state_snapshot(&root), before);
        assert!(!admission.project_root.exists());
        assert!(!root.join(INVENTORY_FILE).exists());
    }

    #[cfg(unix)]
    fn frozen_source_fixture(root: &Path, marker: u8) -> (NativeSessionAdmission, Vec<u8>) {
        use crate::supply_chain::module_resolution_graph::file_resolution::source_graph::{
            GraphOptions, capsule, capture,
        };

        let mut admission = fixture(root, marker);
        std::fs::create_dir_all(&admission.project_root).unwrap();
        std::fs::write(
            admission.project_root.join("package.json"),
            r#"{"type":"module"}"#,
        )
        .unwrap();
        std::fs::write(&admission.entrypoint, "import './dep.js';\n").unwrap();
        std::fs::write(
            admission.project_root.join("dep.js"),
            "export const retainedValue = 42;\n",
        )
        .unwrap();
        let graph = capture(&admission.project_root, "index.js", GraphOptions::default()).unwrap();
        let capsule = capsule::encode(&graph).unwrap();
        admission.source_capsule =
            Some(retain_native_session_source_capsule(root, &graph).unwrap());
        (admission, capsule.bytes().to_vec())
    }

    #[cfg(unix)]
    #[test]
    fn source_capsule_forensics_survive_parent_loss_and_source_removal() {
        use base64::Engine as _;

        for with_journal in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let (admission, original) = frozen_source_fixture(&root, 151);
            let binding = admission.source_capsule.as_ref().unwrap();
            let mut guard =
                NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            if with_journal {
                let mut journal = guard.prepare_effect_journal().unwrap();
                let request_hash = format!("sha256:{}", "ef".repeat(32));
                journal.admit(0, "fs_write", &request_hash).unwrap();
                journal.complete(0).unwrap();
                journal.admit(1, "network_request", &request_hash).unwrap();
            }
            // Model process loss before any signed outcome. Retained source is
            // evidence of admission, never a claim that the guest completed.
            guard.finished = true;
            drop(guard);
            std::fs::rename(&admission.project_root, temp.path().join("retired-source")).unwrap();
            let before = forensic_state_snapshot(&root);
            let export =
                export_native_session_forensics_at(&root, &admission.session_nonce).unwrap();
            assert_eq!(
                export.bundle.schema_version,
                "franken-node/native-session-forensics/v3"
            );
            assert_eq!(
                base64::engine::general_purpose::STANDARD
                    .decode(export.bundle.source_capsule_base64.as_ref().unwrap())
                    .unwrap(),
                original
            );
            assert!(export.bundle.outcome.is_none());
            assert_eq!(export.verification.outcome_kind, "pending");
            let sources = export.verification.source_capsule.as_ref().unwrap();
            assert_eq!(sources.graph_input_hash, binding.graph_input_hash);
            assert_eq!(sources.capsule_bytes, binding.capsule_bytes);
            assert!(!sources.graph_hash_recomputed);
            assert!(!export.verification.replay_certified);
            assert!(!export.verification.quiescence_certified);
            assert!(!export.verification.historical_completeness);
            assert_eq!(export.verification.durable_journal.is_some(), with_journal);
            if let Some(journal) = &export.verification.durable_journal {
                assert_eq!(journal.admitted_provider_calls, 2);
                assert_eq!(journal.returned_provider_calls, 1);
                assert_eq!(journal.indeterminate_provider_calls, 1);
            }
            let discovery = read_native_session_forensics_at(&root, None).unwrap();
            assert!(
                discovery.source_errors.is_empty(),
                "{:?}",
                discovery.source_errors
            );
            assert_eq!(
                discovery.records[0].admission.source_capsule.as_ref(),
                Some(binding)
            );
            assert_eq!(discovery.records[0].durable_journal.is_some(), with_journal);
            assert_eq!(forensic_state_snapshot(&root), before);
            assert!(!admission.project_root.exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn source_capsule_admission_rejects_missing_tampered_or_misbound_sources() {
        for mutation in 0..6 {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let (mut admission, original) = frozen_source_fixture(&root, 152);
            let binding = admission.source_capsule.as_ref().unwrap();
            let path = source_capsule_path(&root, binding).unwrap();
            match mutation {
                0 => std::fs::rename(&path, path.with_extension("retained")).unwrap(),
                1 => {
                    let mut changed = original;
                    *changed.last_mut().unwrap() ^= 1;
                    std::fs::write(&path, changed).unwrap();
                }
                2 => admission.entrypoint = admission.project_root.join("dep.js"),
                3 => {
                    admission.source_capsule.as_mut().unwrap().graph_input_hash =
                        format!("sha256:{}", "ba".repeat(32))
                }
                4 => admission.source_capsule.as_mut().unwrap().capsule_bytes += 1,
                5 => {
                    admission.source_capsule.as_mut().unwrap().capsule_digest =
                        "sha256:../../outside".to_owned()
                }
                _ => unreachable!(),
            }
            let before = forensic_state_snapshot(&root);
            assert!(
                NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).is_err(),
                "mutation {mutation}"
            );
            assert!(!admission_receipt_path(&root, &admission.session_nonce).exists());
            assert_eq!(forensic_state_snapshot(&root), before);
        }
    }

    #[cfg(unix)]
    #[test]
    fn source_capsule_retention_reuses_exact_bytes_and_enforces_aggregate_capacity() {
        use crate::supply_chain::module_resolution_graph::file_resolution::source_graph::{
            GraphOptions, capture,
        };

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let (admission, original) = frozen_source_fixture(&root, 153);
        let binding = admission.source_capsule.as_ref().unwrap();
        let graph = capture(&admission.project_root, "index.js", GraphOptions::default()).unwrap();
        let before = forensic_state_snapshot(&root);
        assert_eq!(
            retain_native_session_source_capsule(&root, &graph).unwrap(),
            *binding
        );
        assert_eq!(forensic_state_snapshot(&root), before);
        let directory = root.join(SOURCE_CAPSULE_DIRECTORY);
        assert!(check_source_capsule_capacity(&directory, 0, 0, 1, original.len()).is_ok());
        assert!(check_source_capsule_capacity(&directory, 1, 0, 1, original.len()).is_err());
        assert!(check_source_capsule_capacity(&directory, 0, 1, 1, original.len()).is_err());
        // An incomplete retained object is still charged and never repaired.
        let path = source_capsule_path(&root, binding).unwrap();
        std::fs::write(&path, &original[..12]).unwrap();
        assert!(retain_native_session_source_capsule(&root, &graph).is_err());
        assert_eq!(std::fs::read(path).unwrap(), original[..12]);
    }

    #[cfg(unix)]
    #[test]
    fn retained_source_capsule_proof_matches_unchanged_file_and_detects_tampering() {
        use crate::supply_chain::module_resolution_graph::file_resolution::source_graph::{
            GraphOptions, capture,
        };

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let (admission, original) = frozen_source_fixture(&root, 155);
        let graph = capture(&admission.project_root, "index.js", GraphOptions::default()).unwrap();
        let proof = retain_native_session_source_capsule_with_proof(&root, &graph).unwrap();
        assert_eq!(proof.encoded_capsule().bytes(), original.as_slice());
        assert!(proof.verify_on_disk(&root, &admission));

        // Wrong entrypoint must reject proof.
        let mut wrong_entry = admission.clone();
        wrong_entry.entrypoint = admission.project_root.join("other.js");
        assert!(!proof.verify_on_disk(&root, &wrong_entry));

        // Tampering with the retained capsule invalidates the proof immediately.
        let path = source_capsule_path(&root, proof.binding()).unwrap();
        std::fs::write(&path, &original[..12]).unwrap();
        assert!(!proof.verify_on_disk(&root, &admission));
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_capacity_statat_enforces_limits_and_rejects_unsafe_entries() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("cap-dir");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let file_a = dir.join("a.bin");
        std::fs::write(&file_a, b"0123456789").unwrap();
        std::fs::set_permissions(&file_a, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(check_source_capsule_capacity(&dir, 0, 0, 1, 10).is_ok());
        assert!(check_source_capsule_capacity(&dir, 1, 0, 1, 10).is_err());
        assert!(check_source_capsule_capacity(&dir, 0, 1, 1, 10).is_err());
        assert!(check_admission_record_capacity(&dir, 0, 0, 1, 10).is_ok());

        // Group-readable file must be refused.
        std::fs::set_permissions(&file_a, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(check_source_capsule_capacity(&dir, 0, 0, 10, 1024).is_err());
        std::fs::set_permissions(&file_a, std::fs::Permissions::from_mode(0o600)).unwrap();

        // Hardlink (nlink > 1) must be refused.
        let link_path = temp.path().join("hardlink.bin");
        std::fs::hard_link(&file_a, &link_path).unwrap();
        assert!(check_admission_record_capacity(&dir, 0, 0, 10, 1024).is_err());
        std::fs::remove_file(&link_path).unwrap();

        // Symlink inside capacity directory must be refused.
        let sym_path = dir.join("sym.bin");
        symlink(&file_a, &sym_path).unwrap();
        assert!(check_source_capsule_capacity(&dir, 0, 0, 10, 1024).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn database_state_fingerprint_detects_raw_sql_mutation_and_capture_tampering() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let (admission, _) = frozen_source_fixture(&root, 156);
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        let (expected_fp, count, bytes) = guard
            .post_admit_usage
            .clone()
            .expect("clean admission captures post-admit DB fingerprint");
        assert_eq!(count, 1);
        assert!(bytes > MAX_OUTCOME_BYTES);
        assert_eq!(
            database_state_fingerprint(&root).as_ref(),
            Some(&expected_fp)
        );

        // A raw SQL mutation between admit and finish must invalidate the DB fingerprint.
        let conn = open_inventory_unlocked(&root, false).unwrap().unwrap();
        let mut tx = conn.transaction().unwrap();
        tx.execute_with_params(
            "INSERT INTO native_sessions(session_nonce, admission_json, outcome_json) VALUES (?1, ?2, ?3);",
            &[
                SqliteValue::Text("01900000-0000-7000-8000-000000000999".into()),
                SqliteValue::Text("{}".into()),
                SqliteValue::Text("{}".into()),
            ],
        )
        .unwrap();
        tx.commit().unwrap();
        assert_ne!(
            database_state_fingerprint(&root).as_ref(),
            Some(&expected_fp),
            "raw SQL write must invalidate post-admit DB fingerprint"
        );

        // Weakening keys/ directory permissions invalidates the cached root and fails closed.
        use std::os::unix::fs::PermissionsExt as _;
        let keys_dir = root.join("keys");
        std::fs::set_permissions(&keys_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let outcome = NativeSessionOutcome {
            observed_at: Utc::now(),
            kind: NativeSessionOutcomeKind::Completed,
            process: NativeSessionProcessObservation::WorkerReaped,
            containment_empty_observed: false,
            effects: NativeSessionEffectObservation::NotStarted,
            panic_evidence: None,
        };
        assert!(
            retain_outcome_receipt_with_cached_root(
                &root,
                &admission,
                &outcome,
                guard.cached_root.as_ref(),
            )
            .is_err(),
            "world-readable keys/ directory must fail closed instead of trusting cached signing root"
        );
        std::fs::set_permissions(&keys_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        // Tampering with identity-capture invalidates cached signing proof and fails closed.
        std::fs::write(&admission.identity_capture_path, b"corrupted").unwrap();
        assert!(
            retain_outcome_receipt_with_cached_root(
                &root,
                &admission,
                &outcome,
                guard.cached_root.as_ref(),
            )
            .is_err(),
            "tampered identity capture must fail closed instead of trusting cached signing root"
        );
        guard.finished = true;
        drop(guard);
    }

    #[cfg(unix)]
    #[test]
    fn source_capsule_forensics_refuse_lost_tampered_or_unsafe_retention_without_repair() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        for mutation in 0..5 {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let (admission, original) = frozen_source_fixture(&root, 154);
            let mut guard =
                NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            guard.finished = true;
            drop(guard);
            let path =
                source_capsule_path(&root, admission.source_capsule.as_ref().unwrap()).unwrap();
            let retained = path.with_extension("retained");
            match mutation {
                0 => std::fs::rename(&path, &retained).unwrap(),
                1 => {
                    let mut changed = original;
                    *changed.last_mut().unwrap() ^= 1;
                    std::fs::write(&path, changed).unwrap();
                }
                2 => {
                    std::fs::rename(&path, &retained).unwrap();
                    symlink(&retained, &path).unwrap();
                }
                3 => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap()
                }
                4 => std::fs::hard_link(&path, &retained).unwrap(),
                _ => unreachable!(),
            }
            let before = forensic_state_snapshot(&root);
            assert!(export_native_session_forensics_at(&root, &admission.session_nonce).is_err());
            let report = read_native_session_forensics_at(&root, None).unwrap();
            assert_eq!(report.records.len(), 1);
            assert_eq!(
                report.records[0].status,
                NativeSessionForensicStatus::PendingLivenessUnknown
            );
            assert!(report.source_errors.iter().any(|error| {
                error.kind == NativeSessionForensicErrorKind::SourceCapsuleInvalid
            }));
            assert_eq!(forensic_state_snapshot(&root), before);
        }
    }

    #[test]
    fn forensic_export_durable_journal_survives_parent_loss_without_terminal_claims() {
        use super::super::native_session_journal::native_session_effect_journal_path;
        use std::io::Write as _;

        for torn_tail in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let admission = fixture(&root, 143);
            std::fs::create_dir(&admission.project_root).unwrap();
            std::fs::write(&admission.entrypoint, "original source").unwrap();
            let mut guard =
                NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            let mut journal = guard.prepare_effect_journal().unwrap();
            let request_hash = format!("sha256:{}", "bc".repeat(32));
            journal.admit(0, "fs_write", &request_hash).unwrap();
            journal.complete(0).unwrap();
            journal.admit(1, "network_request", &request_hash).unwrap();
            // Model abrupt supervisor loss: no Drop-derived or signed terminal
            // observation is invented from the retained provider prefix.
            guard.finished = true;
            drop(guard);
            drop(journal);
            let journal_path = native_session_effect_journal_path(&root, &admission.session_nonce);
            if torn_tail {
                let mut file = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&journal_path)
                    .unwrap();
                file.write_all(b"{\"payload_json\":\"unfinished").unwrap();
                file.sync_all().unwrap();
            }
            std::fs::rename(&admission.project_root, temp.path().join("retired-source")).unwrap();
            let before = forensic_state_snapshot(&root);
            let export =
                export_native_session_forensics_at(&root, &admission.session_nonce).unwrap();
            assert_eq!(
                export.bundle.schema_version,
                "franken-node/native-session-forensics/v2"
            );
            assert_eq!(
                export.bundle.journal_jsonl.as_ref().unwrap().as_bytes(),
                std::fs::read(&journal_path).unwrap()
            );
            assert!(export.bundle.outcome.is_none());
            assert_eq!(export.verification.outcome_kind, "pending");
            assert_eq!(export.verification.completed_provider_calls, None);
            assert_eq!(export.verification.indeterminate_provider_calls, None);
            let journal = export.verification.durable_journal.unwrap();
            assert_eq!(journal.admitted_provider_calls, 2);
            assert_eq!(journal.returned_provider_calls, 1);
            assert_eq!(journal.indeterminate_provider_calls, 1);
            assert_eq!(journal.trailing_partial_record, torn_tail);
            assert!(
                !journal.replay_certified
                    && !journal.quiescence_certified
                    && !journal.historical_completeness
            );
            let discovery = read_native_session_forensics_at(&root, None).unwrap();
            assert!(
                discovery.source_errors.is_empty(),
                "{:?}",
                discovery.source_errors
            );
            assert_eq!(discovery.records.len(), 1);
            let record = &discovery.records[0];
            assert_eq!(
                record.status,
                NativeSessionForensicStatus::PendingLivenessUnknown
            );
            assert!(record.outcome.is_none());
            assert_eq!(
                record
                    .durable_journal
                    .as_ref()
                    .unwrap()
                    .admitted_provider_calls,
                2
            );
            assert_eq!(
                record
                    .durable_journal
                    .as_ref()
                    .unwrap()
                    .trailing_partial_record,
                torn_tail
            );
            assert_eq!(forensic_state_snapshot(&root), before);
            assert!(!root.join(OUTCOME_RECEIPT_DIRECTORY).exists());
        }
    }

    #[test]
    fn forensic_export_refuses_corrupt_and_cross_session_journals_without_repair() {
        use super::super::native_session_journal::{
            NATIVE_SESSION_EFFECT_JOURNAL_BYTE_CAP, NativeSessionEffectJournalWriter,
            native_session_effect_journal_path,
        };
        use std::io::Write as _;

        for mutation in 0..5 {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let admission = fixture(&root, 144);
            let mut guard =
                NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            let mut journal = guard.prepare_effect_journal().unwrap();
            journal
                .admit(0, "fs_read", &format!("sha256:{}", "bc".repeat(32)))
                .unwrap();
            journal.complete(0).unwrap();
            guard.finished = true;
            drop(guard);
            drop(journal);
            let path = native_session_effect_journal_path(&root, &admission.session_nonce);
            let original = std::fs::read_to_string(&path).unwrap();
            match mutation {
                0 => {
                    let (first, remaining) = original.split_once('\n').unwrap();
                    let mut envelope: serde_json::Value = serde_json::from_str(first).unwrap();
                    envelope["signature_hex"] = serde_json::Value::String("00".repeat(64));
                    std::fs::write(
                        &path,
                        format!("{}\n{remaining}", serde_json::to_string(&envelope).unwrap()),
                    )
                    .unwrap();
                }
                1 | 2 => {
                    let foreign_root = temp.path().join("foreign-evidence");
                    ensure_runtime_evidence_directory(&foreign_root, true).unwrap();
                    let nonce = if mutation == 1 {
                        uuid::Uuid::now_v7().to_string()
                    } else {
                        admission.session_nonce.clone()
                    };
                    let digest = if mutation == 1 {
                        admission_digest(&admission).unwrap()
                    } else {
                        "ef".repeat(32)
                    };
                    let mut foreign = NativeSessionEffectJournalWriter::create(
                        &foreign_root,
                        &nonce,
                        &admission.product_root_key_id,
                        &digest,
                        ed25519_dalek::SigningKey::from_bytes(&[17; 32]),
                    )
                    .unwrap();
                    foreign
                        .admit(0, "network_request", &format!("sha256:{}", "bc".repeat(32)))
                        .unwrap();
                    drop(foreign);
                    let foreign_bytes = std::fs::read_to_string(
                        native_session_effect_journal_path(&foreign_root, &nonce),
                    )
                    .unwrap();
                    let replaced = if mutation == 1 {
                        format!(
                            "{}\n{}\n",
                            original.lines().next().unwrap(),
                            foreign_bytes.lines().nth(1).unwrap()
                        )
                    } else {
                        foreign_bytes
                    };
                    std::fs::write(&path, replaced).unwrap();
                }
                3 => {
                    std::fs::OpenOptions::new()
                        .append(true)
                        .open(&path)
                        .unwrap()
                        .write_all(b"{}\n")
                        .unwrap();
                }
                4 => std::fs::write(
                    &path,
                    vec![b'x'; NATIVE_SESSION_EFFECT_JOURNAL_BYTE_CAP + 1],
                )
                .unwrap(),
                _ => unreachable!(),
            }
            let before = forensic_state_snapshot(&root);
            assert!(
                export_native_session_forensics_at(&root, &admission.session_nonce).is_err(),
                "mutation {mutation}"
            );
            let report = read_native_session_forensics_at(&root, None).unwrap();
            assert_eq!(report.records.len(), 1);
            assert_eq!(
                report.records[0].status,
                NativeSessionForensicStatus::PendingLivenessUnknown
            );
            assert!(report.records[0].durable_journal.is_none());
            assert!(
                report
                    .source_errors
                    .iter()
                    .any(|error| error.kind == NativeSessionForensicErrorKind::JournalInvalid)
            );
            assert_eq!(forensic_state_snapshot(&root), before);
        }
    }

    #[test]
    fn forensic_export_preserves_signed_interruption_and_panic_after_source_removal() {
        for panicked in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let admission = fixture(&root, 135);
            std::fs::create_dir(&admission.project_root).unwrap();
            std::fs::write(&admission.entrypoint, "console.log('original guest');").unwrap();
            let evidence = forensic_interruption(&admission);
            let mut guard =
                NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            guard.worker_started();
            guard.worker_reaped();
            if panicked {
                guard
                    .finish_panicked(
                        NativeSessionEffectObservation::Unknown,
                        NativeSessionPanicEvidence::from_validated_response(
                            "native panic diagnostic",
                            true,
                            evidence.entries[..1].to_vec(),
                        ),
                    )
                    .unwrap();
            } else {
                guard.finish(
                    NativeSessionOutcomeKind::Interrupted,
                    NativeSessionEffectObservation::Interrupted {
                        evidence: Box::new(evidence),
                    },
                );
            }
            drop(guard);
            std::fs::rename(&admission.project_root, temp.path().join("retired-source")).unwrap();
            let retained: NativeSessionOutcomeReceipt = serde_json::from_slice(
                &std::fs::read(outcome_receipt_path(&root, &admission.session_nonce)).unwrap(),
            )
            .unwrap();
            let before = forensic_state_snapshot(&root);
            let export =
                export_native_session_forensics_at(&root, &admission.session_nonce).unwrap();
            let exported = export.bundle.outcome.as_ref().unwrap();
            assert_eq!(exported.payload_json, retained.payload_json().unwrap());
            assert_eq!(exported.signature_hex, retained.signature_hex);
            assert_eq!(
                export.bundle.admission_json,
                serde_json::to_string(&admission).unwrap()
            );
            assert_eq!(export.verification.session_nonce, admission.session_nonce);
            assert_eq!(
                export.verification.outcome_kind,
                if panicked { "panicked" } else { "interrupted" }
            );
            assert_eq!(export.verification.completed_provider_calls, Some(1));
            assert_eq!(
                export.verification.indeterminate_provider_calls,
                Some(usize::from(!panicked))
            );
            assert!(!export.verification.replay_certified);
            assert!(!export.verification.quiescence_certified);
            assert!(!export.verification.historical_completeness);
            assert_eq!(
                forensic_state_snapshot(&root),
                before,
                "export must not alter retained state"
            );
            assert!(!admission.project_root.exists());
        }
    }

    #[test]
    fn forensic_export_keeps_pending_and_unsigned_database_outcomes_nonterminal() {
        for unsigned_projection in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let admission = fixture(&root, 136);
            let mut guard =
                NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            // Model abrupt parent loss before a signed outcome was retained.
            guard.finished = true;
            drop(guard);
            if unsigned_projection {
                let connection = open_inventory(&root, false).unwrap().unwrap();
                let mut tx = connection.transaction().unwrap();
                tx.execute_with_params(
                    "UPDATE native_sessions SET outcome_json = ?1 WHERE session_nonce = ?2;",
                    &[
                        SqliteValue::Text(
                            serde_json::to_string(&terminal_outcome()).unwrap().into(),
                        ),
                        SqliteValue::Text(admission.session_nonce.clone().into()),
                    ],
                )
                .unwrap();
                tx.commit().unwrap();
                drop(tx);
                drop(connection);
                protect_sidecars(&root).unwrap();
            }
            let before = forensic_state_snapshot(&root);
            let export =
                export_native_session_forensics_at(&root, &admission.session_nonce).unwrap();
            assert!(export.bundle.outcome.is_none());
            assert!(serde_json::to_value(&export.bundle).unwrap()["outcome"].is_null());
            assert_eq!(export.verification.outcome_kind, "pending");
            assert_eq!(export.verification.completed_provider_calls, None);
            assert_eq!(export.verification.indeterminate_provider_calls, None);
            assert!(!export.verification.replay_certified);
            assert_eq!(forensic_state_snapshot(&root), before);
            assert!(!root.join(OUTCOME_RECEIPT_DIRECTORY).exists());
        }
    }

    #[test]
    fn forensic_export_retains_signed_observation_without_recovering_database() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 137);
        let guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        abandon_after_receipt(&root, guard, &terminal_outcome());
        let before = forensic_state_snapshot(&root);
        let export = export_native_session_forensics_at(&root, &admission.session_nonce).unwrap();
        assert_eq!(export.verification.outcome_kind, "control_stopped");
        assert!(export.bundle.outcome.is_some());
        assert_eq!(forensic_state_snapshot(&root), before);
        let connection = open_inventory(&root, false).unwrap().unwrap();
        assert!(read_records(&connection).unwrap()[0].outcome.is_none());
    }

    #[test]
    fn forensic_export_bounds_corrupt_json_columns_and_refuses_duplicate_rows() {
        for mutation in 0..5 {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let admission = fixture(&root, 141);
            let mut guard =
                NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            guard.finished = true;
            drop(guard);
            let connection = open_inventory(&root, false).unwrap().unwrap();
            let mut tx = connection.transaction().unwrap();
            if mutation == 4 {
                // Preserve the original table while modelling a corrupt schema
                // that no longer enforces session-nonce uniqueness.
                tx.execute("ALTER TABLE native_sessions RENAME TO retained_native_sessions;")
                    .unwrap();
                tx.execute("CREATE TABLE native_sessions (session_nonce TEXT NOT NULL, admission_json TEXT NOT NULL, outcome_json TEXT);").unwrap();
                for _ in 0..4 {
                    tx.execute(
                        "INSERT INTO native_sessions SELECT * FROM retained_native_sessions;",
                    )
                    .unwrap();
                }
            } else {
                let (query, value) = match mutation {
                    0 => (
                        "UPDATE native_sessions SET admission_json = ?1 WHERE session_nonce = ?2;",
                        SqliteValue::Text("x".repeat(MAX_ADMISSION_BYTES + 1).into()),
                    ),
                    1 => (
                        "UPDATE native_sessions SET outcome_json = ?1 WHERE session_nonce = ?2;",
                        SqliteValue::Text("x".repeat(MAX_OUTCOME_BYTES + 1).into()),
                    ),
                    2 => (
                        "UPDATE native_sessions SET admission_json = ?1 WHERE session_nonce = ?2;",
                        SqliteValue::Blob(vec![b'7'].into()),
                    ),
                    3 => (
                        "UPDATE native_sessions SET outcome_json = ?1 WHERE session_nonce = ?2;",
                        SqliteValue::Blob(vec![b'7'].into()),
                    ),
                    _ => unreachable!(),
                };
                tx.execute_with_params(
                    query,
                    &[
                        value,
                        SqliteValue::Text(admission.session_nonce.clone().into()),
                    ],
                )
                .unwrap();
            }
            tx.commit().unwrap();
            drop(tx);
            drop(connection);
            protect_sidecars(&root).unwrap();
            let before = forensic_state_snapshot(&root);
            let error = export_native_session_forensics_at(&root, &admission.session_nonce)
                .err()
                .unwrap();
            assert!(
                error.to_string().contains(if mutation == 4 {
                    "no unique retained admission"
                } else {
                    "invalid type or exceeds its byte bound"
                }),
                "mutation {mutation}: {error:#}"
            );
            assert_eq!(forensic_state_snapshot(&root), before);
        }
    }

    #[test]
    fn forensic_export_refuses_missing_or_altered_authority_and_conflicting_projection() {
        for mutation in 0..8 {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let admission = fixture(&root, 138);
            let guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            abandon_after_receipt(&root, guard, &terminal_outcome());
            let admission_path = admission_receipt_path(&root, &admission.session_nonce);
            let outcome_path = outcome_receipt_path(&root, &admission.session_nonce);
            match mutation {
                0 => std::fs::rename(&admission_path, admission_path.with_extension("retained"))
                    .unwrap(),
                1 => std::fs::rename(
                    &admission.identity_capture_path,
                    admission.identity_capture_path.with_extension("retained"),
                )
                .unwrap(),
                2 => {
                    let mut identity: RuntimeEvidenceIdentityCapture = serde_json::from_slice(
                        &std::fs::read(&admission.identity_capture_path).unwrap(),
                    )
                    .unwrap();
                    identity.session_nonce = uuid::Uuid::now_v7().to_string();
                    std::fs::write(
                        &admission.identity_capture_path,
                        serde_json::to_vec(&identity).unwrap(),
                    )
                    .unwrap();
                }
                3 | 6 => {
                    let connection = open_inventory(&root, false).unwrap().unwrap();
                    let mut tx = connection.transaction().unwrap();
                    let (query, json) = if mutation == 3 {
                        let mut altered = admission.clone();
                        altered
                            .dependency_ids
                            .push("unsigned-dependency".to_owned());
                        (
                            "UPDATE native_sessions SET admission_json = ?1 WHERE session_nonce = ?2;",
                            serde_json::to_string(&altered).unwrap(),
                        )
                    } else {
                        let mut altered = terminal_outcome();
                        altered.kind = NativeSessionOutcomeKind::Completed;
                        (
                            "UPDATE native_sessions SET outcome_json = ?1 WHERE session_nonce = ?2;",
                            serde_json::to_string(&altered).unwrap(),
                        )
                    };
                    tx.execute_with_params(
                        query,
                        &[
                            SqliteValue::Text(json.into()),
                            SqliteValue::Text(admission.session_nonce.clone().into()),
                        ],
                    )
                    .unwrap();
                    tx.commit().unwrap();
                    drop(tx);
                    drop(connection);
                    protect_sidecars(&root).unwrap();
                }
                4 | 5 => {
                    let mut receipt: NativeSessionOutcomeReceipt =
                        serde_json::from_slice(&std::fs::read(&outcome_path).unwrap()).unwrap();
                    if mutation == 4 {
                        receipt.outcome.kind = NativeSessionOutcomeKind::Completed;
                    } else {
                        receipt.signature_hex = "00".repeat(64);
                    }
                    std::fs::write(&outcome_path, serde_json::to_vec(&receipt).unwrap()).unwrap();
                }
                7 => {
                    let key = root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH);
                    std::fs::rename(&key, key.with_extension("retained")).unwrap();
                }
                _ => unreachable!(),
            }
            let before = forensic_state_snapshot(&root);
            assert!(
                export_native_session_forensics_at(&root, &admission.session_nonce).is_err(),
                "mutation {mutation}"
            );
            assert_eq!(
                forensic_state_snapshot(&root),
                before,
                "refusal must not repair or replace authority"
            );
        }
    }

    #[test]
    fn forensic_export_rejects_nonce_aliases_unknown_sessions_and_absent_state() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("absent-evidence");
        let canonical = uuid::Uuid::now_v7().to_string();
        for nonce in [
            "../session".to_owned(),
            uuid::Uuid::nil().to_string(),
            canonical.to_uppercase(),
            format!("{{{canonical}}}"),
            canonical.replace('-', ""),
            canonical,
        ] {
            assert!(export_native_session_forensics_at(&missing, &nonce).is_err());
            assert!(!missing.exists());
        }
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 139);
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        guard.finished = true;
        drop(guard);
        let before = forensic_state_snapshot(&root);
        assert!(
            export_native_session_forensics_at(&root, &uuid::Uuid::now_v7().to_string()).is_err()
        );
        assert_eq!(forensic_state_snapshot(&root), before);
    }

    #[cfg(unix)]
    #[test]
    fn forensic_export_refuses_symlinks_and_insecure_permissions_without_repair() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 140);
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        guard.finished = true;
        drop(guard);
        let alias = temp.path().join("evidence-alias");
        symlink(&root, &alias).unwrap();
        assert!(export_native_session_forensics_at(&alias, &admission.session_nonce).is_err());
        let directory = root.join(ADMISSION_RECEIPT_DIRECTORY);
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(export_native_session_forensics_at(&root, &admission.session_nonce).is_err());
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o755
        );
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let database = root.join(INVENTORY_FILE);
        let retained = database.with_extension("retained");
        std::fs::rename(&database, &retained).unwrap();
        symlink(&retained, &database).unwrap();
        assert!(export_native_session_forensics_at(&root, &admission.session_nonce).is_err());
    }

    #[test]
    fn forensic_discovery_recovers_signed_admissions_when_projection_is_unavailable() {
        for with_outcome in [false, true] {
            for fault in 0..4 {
                let temp = tempfile::tempdir().unwrap();
                let root = temp.path().join("evidence");
                let admission = fixture(&root, 175);
                let mut guard =
                    NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
                let outcome = terminal_outcome();
                if with_outcome {
                    abandon_after_receipt(&root, guard, &outcome);
                } else {
                    guard.finished = true;
                    drop(guard);
                }
                match fault {
                    0 | 2 => {
                        retire_forensic_inventory(&root, &temp.path().join("retired-inventory"));
                        if fault == 2 {
                            create_new_runtime_evidence_private_file(
                                &root.join(INVENTORY_FILE),
                                &[b'x'; 4096],
                            )
                            .unwrap();
                        }
                    }
                    1 | 3 => {
                        let connection = open_inventory(&root, false).unwrap().unwrap();
                        let mut tx = connection.transaction().unwrap();
                        tx.execute(
                            "ALTER TABLE native_sessions RENAME TO retained_native_sessions;",
                        )
                        .unwrap();
                        if fault == 1 {
                            tx.execute(
                                "CREATE TABLE native_sessions (
                                    session_nonce TEXT NOT NULL,
                                    admission_json TEXT NOT NULL,
                                    outcome_json TEXT
                                );",
                            )
                            .unwrap();
                        }
                        tx.commit().unwrap();
                        drop(tx);
                        drop(connection);
                        protect_sidecars(&root).unwrap();
                    }
                    _ => unreachable!(),
                }
                let before = forensic_state_snapshot(&root);
                let report = read_native_session_forensics_at(&root, Some(&admission.project_root))
                    .unwrap_or_else(|error| {
                        panic!("fault {fault}, signed outcome {with_outcome}: {error:#}")
                    });
                assert_eq!(report.store_present, fault != 0);
                assert!(report.source_errors.iter().any(|error| {
                    error.kind == NativeSessionForensicErrorKind::InventoryUnreadable
                        && error.path == root.join(INVENTORY_FILE)
                }));
                assert!(report.untracked_identity_captures.is_empty());
                let [record] = report.records.as_slice() else {
                    panic!("expected retained admission for fault {fault}: {report:?}");
                };
                assert_eq!(record.admission, admission);
                assert_eq!(record.outcome.as_ref(), with_outcome.then_some(&outcome));
                assert_eq!(record.outcome_recovered_from_receipt, with_outcome);
                assert_eq!(
                    record.status,
                    if with_outcome {
                        NativeSessionForensicStatus::TerminalObservation
                    } else {
                        NativeSessionForensicStatus::PendingLivenessUnknown
                    }
                );
                assert_eq!(
                    report.coverage,
                    "retained_observations_only_not_historical_completeness"
                );
                assert!(!report.replay_certified);
                assert!(!report.quiescence_certified);
                assert_eq!(forensic_state_snapshot(&root), before);
            }
        }
    }

    #[test]
    fn forensic_discovery_unions_partial_projection_without_duplicates_or_repair() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let projected = fixture(&root, 176);
        let retained = fixture(&root, 177);
        for admission in [&projected, &retained] {
            let guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            abandon_after_receipt(&root, guard, &terminal_outcome());
        }
        let complete = read_native_session_forensics_at(&root, None).unwrap();
        assert_eq!(complete.records.len(), 2);
        assert!(complete.source_errors.is_empty());
        let connection = open_inventory(&root, false).unwrap().unwrap();
        let mut tx = connection.transaction().unwrap();
        tx.execute("ALTER TABLE native_sessions RENAME TO retained_native_sessions;")
            .unwrap();
        tx.execute(
            "CREATE TABLE native_sessions (
                session_nonce TEXT PRIMARY KEY NOT NULL,
                admission_json TEXT NOT NULL,
                outcome_json TEXT
            );",
        )
        .unwrap();
        tx.execute_with_params(
            "INSERT INTO native_sessions
             SELECT * FROM retained_native_sessions WHERE session_nonce = ?1;",
            &[SqliteValue::Text(projected.session_nonce.clone().into())],
        )
        .unwrap();
        tx.commit().unwrap();
        drop(tx);
        drop(connection);
        protect_sidecars(&root).unwrap();
        let before = forensic_state_snapshot(&root);
        let report = read_native_session_forensics_at(&root, None).unwrap();
        let nonces: BTreeSet<_> = report
            .records
            .iter()
            .map(|record| record.admission.session_nonce.as_str())
            .collect();
        assert_eq!(report.records.len(), 2);
        assert_eq!(
            nonces,
            BTreeSet::from([
                projected.session_nonce.as_str(),
                retained.session_nonce.as_str(),
            ])
        );
        assert!(report.untracked_identity_captures.is_empty());
        assert!(report.source_errors.iter().any(|error| {
            error.kind == NativeSessionForensicErrorKind::InventoryUnreadable
                && error.session_nonce.as_deref() == Some(retained.session_nonce.as_str())
        }));
        assert_eq!(forensic_state_snapshot(&root), before);
        let connection = open_forensic_inventory(&root).unwrap();
        assert!(
            read_optional_forensic_projection(&connection, &retained.session_nonce)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn forensic_discovery_recovery_authenticates_scope_and_original_root() {
        for mutation in 0..4 {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let operator = temp.path().join("operator");
            let unrelated = temp.path().join("unrelated");
            let admission = operator_fixture(&root, 178, &operator, 0);
            let guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            abandon_after_receipt(&root, guard, &terminal_outcome());
            retire_forensic_inventory(&root, &temp.path().join("retired-inventory"));
            let selected = read_native_session_forensics_at(&root, Some(&operator)).unwrap();
            assert_eq!(selected.records.len(), 1);
            let excluded = read_native_session_forensics_at(&root, Some(&unrelated)).unwrap();
            assert!(excluded.records.is_empty());
            assert!(excluded.untracked_identity_captures.is_empty());
            match mutation {
                0 => {
                    let mut forged = admission.clone();
                    forged.project_root = unrelated.clone();
                    forged.entrypoint = unrelated.join("forged.js");
                    forged.control_scopes = Some(Vec::new());
                    std::fs::write(
                        admission_record_path(&root, &admission.session_nonce),
                        serde_json::to_vec(&forged).unwrap(),
                    )
                    .unwrap();
                }
                1 => {
                    let path = admission_receipt_path(&root, &admission.session_nonce);
                    let mut receipt: NativeSessionAdmissionReceipt =
                        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                    receipt.signature_hex = "00".repeat(64);
                    std::fs::write(&path, serde_json::to_vec(&receipt).unwrap()).unwrap();
                }
                2 => std::fs::rename(
                    admission_receipt_path(&root, &admission.session_nonce),
                    temp.path().join("retired-admission-receipt.json"),
                )
                .unwrap(),
                3 => std::fs::write(root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH), [99; 32])
                    .unwrap(),
                _ => unreachable!(),
            }
            let before = forensic_state_snapshot(&root);
            let report = read_native_session_forensics_at(&root, Some(&operator)).unwrap();
            assert!(report.records.is_empty(), "mutation {mutation}");
            assert!(report.source_errors.iter().any(|error| {
                error.kind == NativeSessionForensicErrorKind::AdmissionRecordInvalid
                    && error.session_nonce.as_deref() == Some(admission.session_nonce.as_str())
            }));
            assert!(!report.replay_certified);
            assert!(!report.quiescence_certified);
            assert_eq!(forensic_state_snapshot(&root), before);
        }
    }

    #[test]
    fn forensic_discovery_recovery_preserves_bad_sources_and_unverified_outcomes() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let damaged = fixture(&root, 179);
        let valid = fixture(&root, 180);
        for admission in [&damaged, &valid] {
            let guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            abandon_after_receipt(&root, guard, &terminal_outcome());
        }
        retire_forensic_inventory(&root, &temp.path().join("retired-inventory"));
        let damaged_path = admission_record_path(&root, &damaged.session_nonce);
        std::fs::write(&damaged_path, b"{invalid").unwrap();
        let outcome_path = outcome_receipt_path(&root, &valid.session_nonce);
        let mut outcome: NativeSessionOutcomeReceipt =
            serde_json::from_slice(&std::fs::read(&outcome_path).unwrap()).unwrap();
        outcome.signature_hex = "00".repeat(64);
        std::fs::write(&outcome_path, serde_json::to_vec(&outcome).unwrap()).unwrap();
        let before = forensic_state_snapshot(&root);
        let report = read_native_session_forensics_at(&root, None).unwrap();
        let [record] = report.records.as_slice() else {
            panic!("valid admission must remain visible despite its bad outcome: {report:?}");
        };
        assert_eq!(record.admission, valid);
        assert_eq!(
            record.status,
            NativeSessionForensicStatus::OutcomeUnverified
        );
        assert!(record.outcome.is_none());
        assert!(!record.outcome_recovered_from_receipt);
        assert!(report.source_errors.iter().any(|error| {
            error.kind == NativeSessionForensicErrorKind::AdmissionRecordInvalid
                && error.path == damaged_path
        }));
        assert!(report.source_errors.iter().any(|error| {
            error.kind == NativeSessionForensicErrorKind::OutcomeReceiptInvalid
                && error.session_nonce.as_deref() == Some(valid.session_nonce.as_str())
        }));
        assert_eq!(report.untracked_identity_captures.len(), 1);
        assert_eq!(
            report.untracked_identity_captures[0].session_nonce,
            damaged.session_nonce
        );
        assert_eq!(forensic_state_snapshot(&root), before);
    }

    #[test]
    fn forensic_discovery_retained_selector_scan_enforces_binding_and_bounds() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 181);
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        guard.finished = true;
        drop(guard);
        let path = admission_record_path(&root, &admission.session_nonce);
        let bytes = std::fs::read(&path).unwrap();
        let before = forensic_state_snapshot(&root);
        let mut report = read_native_session_forensics_at(&root, None).unwrap();
        assert_eq!(
            read_retained_forensic_selectors(&root, 1, bytes.len(), &mut report).unwrap(),
            BTreeSet::from([admission.session_nonce.clone()])
        );
        assert!(read_retained_forensic_selectors(&root, 0, bytes.len(), &mut report).is_err());
        assert!(read_retained_forensic_selectors(&root, 1, bytes.len() - 1, &mut report).is_err());
        assert_eq!(forensic_state_snapshot(&root), before);
        let misbound = root.join(ADMISSION_RECORD_DIRECTORY).join("misbound.json");
        create_new_runtime_evidence_private_file(&misbound, &bytes).unwrap();
        let before = forensic_state_snapshot(&root);
        let report = read_native_session_forensics_at(&root, None).unwrap();
        assert_eq!(report.records.len(), 1);
        assert!(report.source_errors.iter().any(|error| {
            error.kind == NativeSessionForensicErrorKind::AdmissionRecordInvalid
                && error.path == misbound
        }));
        assert_eq!(forensic_state_snapshot(&root), before);
    }

    #[cfg(unix)]
    #[test]
    fn forensic_discovery_recovery_refuses_unsafe_inventory_and_orphaned_sidecars() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        for mutation in 0..4 {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let admission = fixture(&root, 182);
            let mut guard =
                NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            guard.finished = true;
            drop(guard);
            let retired = temp.path().join("retired-inventory");
            retire_forensic_inventory(&root, &retired);
            let database = root.join(INVENTORY_FILE);
            match mutation {
                0 => {
                    create_new_runtime_evidence_private_file(&database, &[b'x'; 4096]).unwrap();
                    std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o644))
                        .unwrap();
                }
                1 => symlink(retired.join(INVENTORY_FILE), &database).unwrap(),
                2 => symlink(
                    retired.join(INVENTORY_FILE),
                    root.join(format!("{INVENTORY_FILE}-wal")),
                )
                .unwrap(),
                3 => std::fs::hard_link(retired.join(INVENTORY_FILE), &database).unwrap(),
                _ => unreachable!(),
            }
            let before = forensic_state_snapshot(&root);
            let report = read_native_session_forensics_at(&root, None).unwrap();
            assert!(report.records.is_empty(), "mutation {mutation}");
            assert!(report.source_errors.iter().any(|error| {
                error.kind == NativeSessionForensicErrorKind::InventoryUnreadable
            }));
            assert_eq!(report.untracked_identity_captures.len(), 1);
            assert_eq!(forensic_state_snapshot(&root), before);
        }
    }

    #[cfg(unix)]
    #[test]
    fn forensic_discovery_recovers_journal_and_sources_without_inventing_terminal_state() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let (admission, _) = frozen_source_fixture(&root, 183);
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        let mut journal = guard.prepare_effect_journal().unwrap();
        let request_hash = format!("sha256:{}", "ef".repeat(32));
        journal.admit(0, "fs_write", &request_hash).unwrap();
        journal.complete(0).unwrap();
        journal.admit(1, "network_request", &request_hash).unwrap();
        drop(journal);
        guard.finished = true;
        drop(guard);
        retire_forensic_inventory(&root, &temp.path().join("retired-inventory"));
        std::fs::rename(&admission.project_root, temp.path().join("retired-project")).unwrap();
        let before = forensic_state_snapshot(&root);
        let report =
            read_native_session_forensics_at(&root, Some(&admission.project_root)).unwrap();
        let [record] = report.records.as_slice() else {
            panic!("expected retained admission and journal: {report:?}");
        };
        assert_eq!(record.admission, admission);
        assert_eq!(
            record.status,
            NativeSessionForensicStatus::PendingLivenessUnknown
        );
        assert!(record.outcome.is_none());
        let journal = record.durable_journal.as_ref().unwrap();
        assert_eq!(journal.admitted_provider_calls, 2);
        assert_eq!(journal.returned_provider_calls, 1);
        assert_eq!(journal.indeterminate_provider_calls, 1);
        assert!(!journal.replay_certified);
        assert!(!journal.quiescence_certified);
        assert!(!journal.historical_completeness);
        assert!(!report.replay_certified);
        assert!(!report.quiescence_certified);
        assert!(report.untracked_identity_captures.is_empty());
        assert_eq!(forensic_state_snapshot(&root), before);
        assert!(!root.join(INVENTORY_FILE).exists());
        assert!(!admission.project_root.exists());
    }

    #[test]
    fn forensic_discovery_missing_state_remains_absent() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("absent-evidence");
        let project = temp.path().join("retired-project");
        let report = read_native_session_forensics_at(&root, Some(&project)).unwrap();
        assert_eq!(report.schema_version, FORENSIC_INVENTORY_SCHEMA);
        assert_eq!(report.project_root.as_ref(), Some(&project));
        assert!(!report.store_present);
        assert!(report.records.is_empty());
        assert!(report.source_errors.is_empty());
        assert!(report.untracked_identity_captures.is_empty());
        assert!(!report.replay_certified);
        assert!(!report.quiescence_certified);
        assert!(!root.exists());
        assert!(!project.exists());
    }

    #[test]
    fn forensic_discovery_pending_never_infers_worker_liveness() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 142);
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        guard.worker_started();
        guard.finished = true;
        drop(guard);
        let before = forensic_state_snapshot(&root);
        let report =
            read_native_session_forensics_at(&root, Some(&admission.project_root)).unwrap();
        assert!(report.source_errors.is_empty());
        assert!(report.untracked_identity_captures.is_empty());
        let [record] = report.records.as_slice() else {
            panic!("expected one authenticated pending admission");
        };
        assert_eq!(record.admission, admission);
        assert_eq!(
            record.status,
            NativeSessionForensicStatus::PendingLivenessUnknown
        );
        assert!(record.outcome.is_none());
        assert!(record.outcome_receipt_path.is_none());
        assert!(!record.outcome_recovered_from_receipt);
        assert!(!report.replay_certified);
        assert!(!report.quiescence_certified);
        assert_eq!(forensic_state_snapshot(&root), before);
    }

    #[test]
    fn forensic_discovery_recovers_exact_signed_observations_without_rewriting_state() {
        for observation in 0..5 {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let admission = fixture(&root, 143);
            let guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            let mut outcome = terminal_outcome();
            match observation {
                0 => {}
                1 => {
                    outcome.kind = NativeSessionOutcomeKind::Panicked;
                    outcome.effects = NativeSessionEffectObservation::Unknown;
                    outcome.panic_evidence =
                        Some(NativeSessionPanicEvidence::from_validated_response(
                            "retained panic",
                            true,
                            forensic_interruption(&admission).entries[..1].to_vec(),
                        ));
                }
                2 => {
                    outcome.kind = NativeSessionOutcomeKind::SupervisionIncomplete;
                    outcome.process = NativeSessionProcessObservation::Unproven;
                    outcome.effects = NativeSessionEffectObservation::Unknown;
                }
                3 => {
                    outcome.kind = NativeSessionOutcomeKind::Interrupted;
                    outcome.effects = NativeSessionEffectObservation::Interrupted {
                        evidence: Box::new(forensic_interruption(&admission)),
                    };
                }
                4 => {
                    outcome.kind = NativeSessionOutcomeKind::SupervisionIncomplete;
                    outcome.process = NativeSessionProcessObservation::NotSpawned;
                    outcome.effects = NativeSessionEffectObservation::NotStarted;
                }
                _ => unreachable!(),
            }
            abandon_after_receipt(&root, guard, &outcome);
            let before = forensic_state_snapshot(&root);
            let report =
                read_native_session_forensics_at(&root, Some(&admission.project_root)).unwrap();
            assert!(report.source_errors.is_empty());
            let [record] = report.records.as_slice() else {
                panic!("expected one authenticated observation");
            };
            assert_eq!(record.admission, admission);
            assert_eq!(record.outcome.as_ref(), Some(&outcome));
            assert_eq!(
                record.status,
                if matches!(observation, 2 | 4) {
                    NativeSessionForensicStatus::SupervisionIncomplete
                } else {
                    NativeSessionForensicStatus::TerminalObservation
                }
            );
            assert_eq!(
                record.admission_receipt_path,
                admission_receipt_path(&root, &admission.session_nonce)
            );
            assert_eq!(
                record.outcome_receipt_path,
                Some(outcome_receipt_path(&root, &admission.session_nonce))
            );
            assert!(record.outcome_recovered_from_receipt);
            assert!(!report.replay_certified);
            assert!(!report.quiescence_certified);
            let export =
                export_native_session_forensics_at(&root, &admission.session_nonce).unwrap();
            assert_eq!(export.verification.session_nonce, admission.session_nonce);
            assert!(!export.verification.replay_certified);
            assert!(!export.verification.quiescence_certified);
            assert_eq!(forensic_state_snapshot(&root), before);
            let connection = open_forensic_inventory(&root).unwrap();
            let (_, projection, _) =
                read_forensic_projection(&connection, &admission.session_nonce).unwrap();
            assert!(matches!(projection, SqliteValue::Null));
        }
    }

    #[test]
    fn forensic_discovery_separates_missing_tampered_and_conflicting_sources() {
        for mutation in 0..6 {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let admission = fixture(&root, 144);
            let guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            abandon_after_receipt(&root, guard, &terminal_outcome());
            let admission_path = admission_receipt_path(&root, &admission.session_nonce);
            let outcome_path = outcome_receipt_path(&root, &admission.session_nonce);
            let expected_kind = match mutation {
                0 => {
                    std::fs::rename(&admission_path, admission_path.with_extension("retained"))
                        .unwrap();
                    NativeSessionForensicErrorKind::AdmissionReceiptMissing
                }
                1 => {
                    let mut receipt: NativeSessionAdmissionReceipt =
                        serde_json::from_slice(&std::fs::read(&admission_path).unwrap()).unwrap();
                    receipt.signature_hex = "00".repeat(64);
                    std::fs::write(&admission_path, serde_json::to_vec(&receipt).unwrap()).unwrap();
                    NativeSessionForensicErrorKind::AdmissionReceiptInvalid
                }
                2 | 3 => {
                    let mut receipt: NativeSessionOutcomeReceipt =
                        serde_json::from_slice(&std::fs::read(&outcome_path).unwrap()).unwrap();
                    if mutation == 2 {
                        receipt.outcome.kind = NativeSessionOutcomeKind::Completed;
                    } else {
                        use ed25519_dalek::Signer as _;
                        let foreign = ed25519_dalek::SigningKey::from_bytes(&[99; 32]);
                        receipt.signature_hex =
                            hex::encode(foreign.sign(&receipt.preimage().unwrap()).to_bytes());
                    }
                    std::fs::write(&outcome_path, serde_json::to_vec(&receipt).unwrap()).unwrap();
                    NativeSessionForensicErrorKind::OutcomeReceiptInvalid
                }
                4 | 5 => {
                    let mut projection = terminal_outcome();
                    projection.kind = NativeSessionOutcomeKind::Completed;
                    let connection = open_inventory(&root, false).unwrap().unwrap();
                    let mut tx = connection.transaction().unwrap();
                    tx.execute_with_params(
                        "UPDATE native_sessions SET outcome_json = ?1 WHERE session_nonce = ?2;",
                        &[
                            SqliteValue::Text(serde_json::to_string(&projection).unwrap().into()),
                            SqliteValue::Text(admission.session_nonce.clone().into()),
                        ],
                    )
                    .unwrap();
                    tx.commit().unwrap();
                    drop(tx);
                    drop(connection);
                    protect_sidecars(&root).unwrap();
                    if mutation == 4 {
                        std::fs::rename(&outcome_path, outcome_path.with_extension("retained"))
                            .unwrap();
                        NativeSessionForensicErrorKind::OutcomeReceiptMissing
                    } else {
                        NativeSessionForensicErrorKind::OutcomeProjectionConflict
                    }
                }
                _ => unreachable!(),
            };
            let before = forensic_state_snapshot(&root);
            let report = read_native_session_forensics_at(&root, None).unwrap();
            assert!(report.source_errors.iter().any(|error| {
                error.kind == expected_kind
                    && error.session_nonce.as_deref() == Some(admission.session_nonce.as_str())
            }));
            if mutation < 2 {
                assert!(report.records.is_empty());
                assert_eq!(report.untracked_identity_captures.len(), 1);
            } else {
                let [record] = report.records.as_slice() else {
                    panic!("expected the authenticated admission despite invalid outcome");
                };
                assert_eq!(record.admission, admission);
                assert_eq!(
                    record.status,
                    NativeSessionForensicStatus::OutcomeUnverified
                );
                assert!(record.outcome.is_none());
                assert!(record.outcome_receipt_path.is_none());
                assert!(!record.outcome_recovered_from_receipt);
            }
            assert_eq!(forensic_state_snapshot(&root), before);
        }
    }

    #[test]
    fn forensic_discovery_authenticates_scope_before_applying_project_filter() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let operator = temp.path().join("operator");
        let unrelated = temp.path().join("unrelated-project");
        let admission = operator_fixture(&root, 145, &operator, 0);
        let guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        abandon_after_receipt(&root, guard, &terminal_outcome());
        let report = read_native_session_forensics_at(&root, Some(&operator)).unwrap();
        assert_eq!(report.records.len(), 1);
        let report = read_native_session_forensics_at(&root, Some(&unrelated)).unwrap();
        assert!(report.records.is_empty());
        assert!(report.source_errors.is_empty());
        assert!(report.untracked_identity_captures.is_empty());

        let mut forged = admission.clone();
        forged.project_root = unrelated.clone();
        forged.entrypoint = unrelated.join("forged.js");
        forged.control_scopes = Some(Vec::new());
        let connection = open_inventory(&root, false).unwrap().unwrap();
        let mut tx = connection.transaction().unwrap();
        tx.execute_with_params(
            "UPDATE native_sessions SET admission_json = ?1 WHERE session_nonce = ?2;",
            &[
                SqliteValue::Text(serde_json::to_string(&forged).unwrap().into()),
                SqliteValue::Text(admission.session_nonce.clone().into()),
            ],
        )
        .unwrap();
        tx.commit().unwrap();
        drop(tx);
        drop(connection);
        protect_sidecars(&root).unwrap();

        let before = forensic_state_snapshot(&root);
        let report = read_native_session_forensics_at(&root, Some(&operator)).unwrap();
        assert!(report.records.is_empty());
        assert!(report.source_errors.iter().any(|error| {
            error.kind == NativeSessionForensicErrorKind::AdmissionReceiptInvalid
                && error.session_nonce.as_deref() == Some(admission.session_nonce.as_str())
        }));
        assert_eq!(report.untracked_identity_captures.len(), 1);
        assert_eq!(forensic_state_snapshot(&root), before);
    }

    #[test]
    fn forensic_discovery_preserves_other_sessions_after_one_corrupt_admission() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let damaged = fixture(&root, 146);
        let valid = fixture(&root, 147);
        for admission in [&damaged, &valid] {
            let guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            abandon_after_receipt(&root, guard, &terminal_outcome());
        }
        let connection = open_inventory(&root, false).unwrap().unwrap();
        let mut tx = connection.transaction().unwrap();
        tx.execute_with_params(
            "UPDATE native_sessions SET admission_json = ?1 WHERE session_nonce = ?2;",
            &[
                SqliteValue::Text("{invalid".to_owned().into()),
                SqliteValue::Text(damaged.session_nonce.clone().into()),
            ],
        )
        .unwrap();
        tx.commit().unwrap();
        drop(tx);
        drop(connection);
        protect_sidecars(&root).unwrap();
        let before = forensic_state_snapshot(&root);
        let report = read_native_session_forensics_at(&root, None).unwrap();
        assert_eq!(report.records.len(), 1);
        assert_eq!(report.records[0].admission, valid);
        assert!(report.source_errors.iter().any(|error| {
            error.kind == NativeSessionForensicErrorKind::AdmissionInvalid
                && error.session_nonce.as_deref() == Some(damaged.session_nonce.as_str())
        }));
        assert_eq!(report.untracked_identity_captures.len(), 1);
        assert_eq!(forensic_state_snapshot(&root), before);
    }

    #[test]
    fn forensic_discovery_keeps_signed_orphans_visible_across_project_filters() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        // Provisioned identity without a durable admission does not prove that
        // any worker started, and cannot supply authenticated project scope.
        let admission = fixture(&root, 149);
        let unrelated = temp.path().join("unrelated-project");
        let before = forensic_state_snapshot(&root);
        let report = read_native_session_forensics_at(&root, Some(&unrelated)).unwrap();
        assert!(!report.store_present);
        assert!(report.records.is_empty());
        assert!(report.source_errors.is_empty());
        let [capture] = report.untracked_identity_captures.as_slice() else {
            panic!("expected one authenticated capture with unknown project scope");
        };
        assert_eq!(capture.session_nonce, admission.session_nonce);
        assert_eq!(
            capture.identity_capture_path,
            admission.identity_capture_path
        );
        assert!(!report.replay_certified);
        assert!(!report.quiescence_certified);
        assert!(!root.join(INVENTORY_FILE).exists());
        assert_eq!(forensic_state_snapshot(&root), before);
    }

    #[cfg(unix)]
    #[test]
    fn forensic_discovery_rejects_unsafe_paths_without_repairing_permissions() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 148);
        let guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        abandon_after_receipt(&root, guard, &terminal_outcome());
        let directory = root.join(OUTCOME_RECEIPT_DIRECTORY);
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(read_native_session_forensics_at(&root, None).is_err());
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o755
        );
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = outcome_receipt_path(&root, &admission.session_nonce);
        let retained = path.with_extension("retained");
        std::fs::rename(&path, &retained).unwrap();
        symlink(&retained, &path).unwrap();
        let report = read_native_session_forensics_at(&root, None).unwrap();
        assert_eq!(report.records.len(), 1);
        assert_eq!(
            report.records[0].status,
            NativeSessionForensicStatus::OutcomeUnverified
        );
        assert!(report.records[0].outcome.is_none());
        assert!(
            report.source_errors.iter().any(|error| {
                error.kind == NativeSessionForensicErrorKind::OutcomeReceiptInvalid
            })
        );
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn launch_outcome_authentication_recovers_only_the_signed_projection() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let operator = temp.path().join("operator");
        let admission = operator_fixture(&root, 112, &operator, 0);
        let guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        let mut outcome = terminal_outcome();
        outcome.kind = NativeSessionOutcomeKind::Completed;
        abandon_after_receipt(&root, guard, &outcome);

        let authenticated = authenticate_native_session_outcome_at(
            &root,
            &admission.session_nonce,
            &admission.project_root,
            &admission.entrypoint,
            &operator,
        )
        .unwrap();
        assert_eq!(authenticated.admission, admission);
        assert_eq!(authenticated.outcome, Some(outcome));
        let connection = open_inventory(&root, false).unwrap().unwrap();
        assert!(
            read_records(&connection).unwrap()[0].outcome.is_none(),
            "authentication must not rewrite the durable projection"
        );
    }

    #[test]
    fn launch_outcome_authentication_binds_nonce_release_and_operator() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let operator = temp.path().join("operator");
        let admission = operator_fixture(&root, 113, &operator, 0);
        let guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        abandon_after_receipt(&root, guard, &terminal_outcome());
        let foreign_nonce = uuid::Uuid::now_v7().to_string();
        let foreign_project = temp.path().join("other-project");
        let foreign_entrypoint = admission.project_root.join("other.js");
        let foreign_operator = temp.path().join("other-operator");
        for (nonce, project, entrypoint, owner) in [
            (
                &foreign_nonce,
                &admission.project_root,
                &admission.entrypoint,
                &operator,
            ),
            (
                &admission.session_nonce,
                &foreign_project,
                &admission.entrypoint,
                &operator,
            ),
            (
                &admission.session_nonce,
                &admission.project_root,
                &foreign_entrypoint,
                &operator,
            ),
            (
                &admission.session_nonce,
                &admission.project_root,
                &admission.entrypoint,
                &foreign_operator,
            ),
        ] {
            assert!(
                authenticate_native_session_outcome_at(&root, nonce, project, entrypoint, owner)
                    .is_err()
            );
        }
        for nonce in [
            "../not-a-launch".to_owned(),
            uuid::Uuid::nil().to_string(),
            format!("{{{}}}", admission.session_nonce),
        ] {
            assert!(
                authenticate_native_session_outcome_at(
                    &root,
                    &nonce,
                    &admission.project_root,
                    &admission.entrypoint,
                    &operator,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn launch_outcome_authentication_requires_both_receipts_and_rejects_forgery() {
        for mutation in 0..5 {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let admission = fixture(&root, 114);
            let guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            abandon_after_receipt(&root, guard, &terminal_outcome());
            let admission_path = admission_receipt_path(&root, &admission.session_nonce);
            let outcome_path = outcome_receipt_path(&root, &admission.session_nonce);
            match mutation {
                0 => {
                    std::fs::rename(&admission_path, admission_path.with_extension("retained"))
                        .unwrap();
                }
                1 => {
                    std::fs::rename(&outcome_path, outcome_path.with_extension("retained"))
                        .unwrap();
                }
                _ => {
                    let mut receipt: NativeSessionOutcomeReceipt =
                        serde_json::from_slice(&std::fs::read(&outcome_path).unwrap()).unwrap();
                    match mutation {
                        2 => receipt.outcome.kind = NativeSessionOutcomeKind::Completed,
                        3 => receipt.signature_hex = "0".repeat(128),
                        4 => {
                            use ed25519_dalek::Signer as _;
                            let foreign = ed25519_dalek::SigningKey::from_bytes(&[99; 32]);
                            receipt.signature_hex =
                                hex::encode(foreign.sign(&receipt.preimage().unwrap()).to_bytes());
                        }
                        _ => unreachable!(),
                    }
                    std::fs::write(&outcome_path, serde_json::to_vec(&receipt).unwrap()).unwrap();
                }
            }
            assert!(
                authenticate_native_session_outcome_at(
                    &root,
                    &admission.session_nonce,
                    &admission.project_root,
                    &admission.entrypoint,
                    &admission.project_root,
                )
                .is_err(),
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn launch_outcome_authentication_refuses_unsigned_database_substitution() {
        for change_admission in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let admission = fixture(&root, 115);
            let guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            let signed = terminal_outcome();
            abandon_after_receipt(&root, guard, &signed);
            let connection = open_inventory(&root, false).unwrap().unwrap();
            let mut tx = connection.transaction().unwrap();
            if change_admission {
                let mut substituted = admission.clone();
                substituted
                    .dependency_ids
                    .push("unadmitted-dependency".into());
                tx.execute_with_params(
                    "UPDATE native_sessions SET admission_json = ?1 WHERE session_nonce = ?2;",
                    &[
                        SqliteValue::Text(serde_json::to_string(&substituted).unwrap().into()),
                        SqliteValue::Text(admission.session_nonce.clone().into()),
                    ],
                )
                .unwrap();
            } else {
                let mut substituted = signed;
                substituted.kind = NativeSessionOutcomeKind::Completed;
                tx.execute_with_params(
                    "UPDATE native_sessions SET outcome_json = ?1 WHERE session_nonce = ?2;",
                    &[
                        SqliteValue::Text(serde_json::to_string(&substituted).unwrap().into()),
                        SqliteValue::Text(admission.session_nonce.clone().into()),
                    ],
                )
                .unwrap();
            }
            tx.commit().unwrap();
            assert!(
                authenticate_native_session_outcome_at(
                    &root,
                    &admission.session_nonce,
                    &admission.project_root,
                    &admission.entrypoint,
                    &admission.project_root,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn launch_outcome_authentication_preserves_effect_indeterminacy() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 116);
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        guard.worker_started();
        guard.worker_reaped();
        guard.finish(
            NativeSessionOutcomeKind::Panicked,
            NativeSessionEffectObservation::Unknown,
        );
        let authenticated = authenticate_native_session_outcome_at(
            &root,
            &admission.session_nonce,
            &admission.project_root,
            &admission.entrypoint,
            &admission.project_root,
        )
        .unwrap();
        let outcome = authenticated.outcome.unwrap();
        assert_eq!(outcome.kind, NativeSessionOutcomeKind::Panicked);
        assert!(outcome.effects.unknown());
        assert!(!terminal_outcome_observed(&admission, &outcome));
    }

    #[test]
    fn signed_panic_forensics_survive_restart_and_reject_detail_tampering() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 121);
        let evidence = NativeSessionPanicEvidence::from_validated_response(
            "native interpreter invariant failed after a returned write",
            true,
            vec![NativeEffectWalEntry {
                sequence: 0,
                effect_kind: "fs_write".to_string(),
                request_hash: format!("sha256:{}", "ab".repeat(32)),
                state: NativeEffectWalState::ProviderReturned,
            }],
        );
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        guard.worker_started();
        guard.worker_reaped();
        guard
            .finish_panicked(NativeSessionEffectObservation::Unknown, evidence.clone())
            .unwrap();
        drop(guard);

        let report = read_inventory_at(&root, None).unwrap();
        assert_eq!(report.pending_sessions, 0);
        assert_eq!(report.unknown_effect_sessions, 1);
        let outcome = report.records[0].outcome.as_ref().unwrap();
        assert_eq!(outcome.kind, NativeSessionOutcomeKind::Panicked);
        assert_eq!(outcome.effects, NativeSessionEffectObservation::Unknown);
        assert_eq!(outcome.panic_evidence.as_ref(), Some(&evidence));
        assert!(!terminal_outcome_observed(&admission, outcome));
        let key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]).verifying_key();
        let receipt = read_outcome_receipt(&root, &admission, &key)
            .unwrap()
            .unwrap();
        for mutation in 0..5 {
            let mut changed = receipt.clone();
            match mutation {
                0 => changed.outcome.panic_evidence = None,
                1 => {
                    let detail = changed.outcome.panic_evidence.as_mut().unwrap();
                    detail.cleanup_successful = false;
                }
                2 => {
                    let detail = changed.outcome.panic_evidence.as_mut().unwrap();
                    detail.host_effect_wal[0].request_hash = format!("sha256:{}", "cd".repeat(32));
                }
                3 => changed
                    .outcome
                    .panic_evidence
                    .as_mut()
                    .unwrap()
                    .host_effect_wal
                    .clear(),
                _ => {
                    changed.outcome.panic_evidence =
                        Some(NativeSessionPanicEvidence::from_validated_response(
                            "replacement panic with a valid standalone digest",
                            true,
                            evidence.host_effect_wal.clone(),
                        ));
                }
            }
            assert!(
                changed.verify(&admission, &key).is_err(),
                "mutation {mutation}"
            );
        }
        for pointer in [
            "/outcome/panic_evidence",
            "/outcome/panic_evidence/host_effect_wal/0",
        ] {
            let mut changed = serde_json::to_value(&receipt).unwrap();
            changed.pointer_mut(pointer).unwrap()["unauthenticated_extension"] =
                serde_json::json!(true);
            assert!(serde_json::from_value::<NativeSessionOutcomeReceipt>(changed).is_err());
        }
        let mut changed = serde_json::to_value(&receipt).unwrap();
        changed["outcome"]["panic_evidence"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<NativeSessionOutcomeReceipt>(changed).is_err());

        let mut inconsistent = outcome.clone();
        inconsistent.effects = NativeSessionEffectObservation::NoAdmittedHostEffects;
        assert!(validate_outcome(&admission, &inconsistent).is_err());
        inconsistent = outcome.clone();
        inconsistent.kind = NativeSessionOutcomeKind::ExecutionFailed;
        assert!(validate_outcome(&admission, &inconsistent).is_err());
        inconsistent = outcome.clone();
        inconsistent
            .panic_evidence
            .as_mut()
            .unwrap()
            .host_effect_wal[0]
            .state = NativeEffectWalState::InterruptedIndeterminate;
        assert!(validate_outcome(&admission, &inconsistent).is_err());
    }

    #[test]
    fn historical_panic_outcome_encoding_and_signature_remain_valid() {
        const HISTORICAL: &str = r#"{"observed_at":"2026-11-13T00:00:00Z","kind":"panicked","process":"worker_reaped","containment_empty_observed":false,"effects":{"kind":"unknown"}}"#;
        let outcome: NativeSessionOutcome = serde_json::from_str(HISTORICAL).unwrap();
        assert!(outcome.panic_evidence.is_none());
        assert_eq!(serde_json::to_string(&outcome).unwrap(), HISTORICAL);
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 122);
        let key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
        let receipt = NativeSessionOutcomeReceipt::issue(&admission, &outcome, &key).unwrap();
        let decoded: NativeSessionOutcomeReceipt =
            serde_json::from_slice(&serde_json::to_vec(&receipt).unwrap()).unwrap();
        decoded.verify(&admission, &key.verifying_key()).unwrap();
        let mut inserted_null = serde_json::to_value(&receipt).unwrap();
        inserted_null["outcome"]["panic_evidence"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<NativeSessionOutcomeReceipt>(inserted_null).is_err());
    }

    #[test]
    fn maximum_panic_wal_and_bounded_utf8_message_fit_signed_outcome() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 123);
        let message = format!(
            "{}🦀{}",
            "x".repeat(MAX_PANIC_MESSAGE_BYTES - 1),
            "y".repeat(8192)
        );
        let wal = (0..NATIVE_SESSION_MAX_EFFECT_WAL_EVENTS / 2)
            .map(|index| NativeEffectWalEntry {
                sequence: u64::try_from(index).unwrap(),
                // Still fits a real 1KiB admission frame, including its nonce,
                // schema, sequence and request hash; no metadata is truncated.
                effect_kind: "x".repeat(700),
                request_hash: format!("sha256:{index:064x}"),
                state: NativeEffectWalState::ProviderReturned,
            })
            .collect::<Vec<_>>();
        let evidence =
            NativeSessionPanicEvidence::from_validated_response(&message, true, wal.clone());
        assert!(evidence.panic_message_truncated);
        assert_eq!(evidence.panic_message.len(), MAX_PANIC_MESSAGE_BYTES - 1);
        assert_eq!(evidence.panic_message_bytes, message.len());
        assert_eq!(
            evidence.panic_message_sha256,
            hex::encode(Sha256::digest(message.as_bytes()))
        );
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        guard.worker_started();
        guard.worker_reaped();
        guard
            .finish_panicked(NativeSessionEffectObservation::Unknown, evidence)
            .unwrap();
        drop(guard);
        let key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]).verifying_key();
        let receipt = read_outcome_receipt(&root, &admission, &key)
            .unwrap()
            .unwrap();
        assert!(bounded_json(&receipt, MAX_OUTCOME_RECEIPT_BYTES).is_ok());
        assert_eq!(receipt.outcome.panic_evidence.unwrap().host_effect_wal, wal);
    }

    #[test]
    fn oversized_panic_detail_reports_failure_but_retains_signed_classification() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 124);
        let evidence = NativeSessionPanicEvidence::from_validated_response(
            "panic with oversized forensic metadata",
            true,
            vec![NativeEffectWalEntry {
                sequence: 0,
                effect_kind: "x".repeat(NATIVE_SESSION_MAX_EFFECT_WAL_STREAM_BYTES + 1),
                request_hash: format!("sha256:{}", "ef".repeat(32)),
                state: NativeEffectWalState::ProviderReturned,
            }],
        );
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        guard.worker_started();
        guard.worker_reaped();
        let error = guard
            .finish_panicked(NativeSessionEffectObservation::Unknown, evidence)
            .unwrap_err();
        assert!(
            error.to_string().contains("classification was preserved"),
            "{error:#}"
        );
        drop(guard);
        let key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]).verifying_key();
        let receipt = read_outcome_receipt(&root, &admission, &key)
            .unwrap()
            .unwrap();
        assert_eq!(receipt.outcome.kind, NativeSessionOutcomeKind::Panicked);
        assert_eq!(
            receipt.outcome.effects,
            NativeSessionEffectObservation::Unknown
        );
        assert!(receipt.outcome.panic_evidence.is_none());
        let report = read_inventory_at(&root, None).unwrap();
        assert_eq!(report.pending_sessions, 0);
        assert_eq!(report.unknown_effect_sessions, 1);
    }

    #[test]
    fn no_effects_panic_observation_requires_reap_and_absent_process_authority() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let mut admission = fixture(&root, 117);
        let mut outcome = NativeSessionOutcome {
            observed_at: Utc::now(),
            kind: NativeSessionOutcomeKind::Panicked,
            process: NativeSessionProcessObservation::WorkerReaped,
            containment_empty_observed: false,
            effects: NativeSessionEffectObservation::NoAdmittedHostEffects,
            panic_evidence: None,
        };
        validate_outcome(&admission, &outcome).unwrap();
        assert!(terminal_outcome_observed(&admission, &outcome));
        assert!(!outcome.effects.unknown());
        for authority in [None, Some(true)] {
            admission.process_spawn_authority_granted = authority;
            assert!(validate_outcome(&admission, &outcome).is_err());
            assert!(!terminal_outcome_observed(&admission, &outcome));
        }
        admission.process_spawn_authority_granted = Some(false);
        outcome.process = NativeSessionProcessObservation::Unproven;
        assert!(validate_outcome(&admission, &outcome).is_err());
        outcome.process = NativeSessionProcessObservation::WorkerReaped;
        for kind in [
            NativeSessionOutcomeKind::Completed,
            NativeSessionOutcomeKind::Interrupted,
        ] {
            outcome.kind = kind;
            assert!(validate_outcome(&admission, &outcome).is_err());
        }
    }

    #[test]
    fn authenticated_no_effects_panic_can_drain_without_erasing_its_failure() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 118);
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        guard.worker_started();
        guard.worker_reaped();
        guard.finish(
            NativeSessionOutcomeKind::Panicked,
            NativeSessionEffectObservation::NoAdmittedHostEffects,
        );
        let checkpoint = actions(1);
        begin_drain_at(
            &root,
            &admission.project_root,
            "node-a",
            "prod",
            &checkpoint,
        )
        .unwrap();
        let drained = finish_drain_at(
            &root,
            &admission.project_root,
            "node-a",
            "prod",
            &checkpoint,
        )
        .unwrap();
        assert_eq!(drained.checkpoint.admitted_sessions, 1);
        assert_eq!(drained.checkpoint.terminal_sessions, 1);
        assert_eq!(drained.checkpoint.indeterminate_sessions, 0);
        assert!(drained.checkpoint.is_complete());
        assert!(!drained.fleet_quiescence_certified);
        let retained = authenticate_native_session_outcome_at(
            &root,
            &admission.session_nonce,
            &admission.project_root,
            &admission.entrypoint,
            &admission.project_root,
        )
        .unwrap();
        let observed = retained.outcome.unwrap();
        assert_eq!(observed.kind, NativeSessionOutcomeKind::Panicked);
        assert_eq!(
            observed.effects,
            NativeSessionEffectObservation::NoAdmittedHostEffects
        );
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
    fn signed_worker_exit_evidence_survives_restart_and_rejects_forged_completion() {
        for cleanup_unproven in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("runtime-evidence");
            let admission = fixture(&root, 133);
            let evidence = NativeEffectInterruptionEvidence {
                schema_version: NATIVE_EFFECT_INTERRUPTION_EVIDENCE_SCHEMA.to_string(),
                session_nonce: admission.session_nonce.clone(),
                terminal_state: if cleanup_unproven {
                    "worker_exit_cleanup_unproven"
                } else {
                    "worker_exit_indeterminate"
                }
                .to_string(),
                replay_certified: false,
                journal_complete: !cleanup_unproven,
                journal_event_cap: NATIVE_SESSION_MAX_EFFECT_WAL_EVENTS,
                completed_effect_count: 1,
                interrupted_effect_count: 1,
                entries: vec![
                    NativeEffectWalEntry {
                        sequence: 0,
                        effect_kind: "fs_write".to_string(),
                        request_hash: format!("sha256:{}", "ab".repeat(32)),
                        state: NativeEffectWalState::ProviderReturned,
                    },
                    NativeEffectWalEntry {
                        sequence: 1,
                        effect_kind: "network_request".to_string(),
                        request_hash: format!("sha256:{}", "cd".repeat(32)),
                        state: NativeEffectWalState::InterruptedIndeterminate,
                    },
                ],
                protocol_error: cleanup_unproven.then(|| "response pipe stayed open".to_string()),
                control_trigger: None,
            };
            let mut guard =
                NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            guard.worker_started();
            guard.worker_reaped();
            guard.finish(
                NativeSessionOutcomeKind::Interrupted,
                NativeSessionEffectObservation::Interrupted {
                    evidence: Box::new(evidence.clone()),
                },
            );
            drop(guard);

            let report = read_inventory_at(&root, None).unwrap();
            assert_eq!(report.pending_sessions, 0);
            assert_eq!(report.unknown_effect_sessions, 1);
            assert!(!report.quiescence_certified);
            let outcome = report.records[0].outcome.as_ref().unwrap();
            assert_eq!(outcome.kind, NativeSessionOutcomeKind::Interrupted);
            assert!(outcome.panic_evidence.is_none());
            assert_eq!(
                outcome.effects,
                NativeSessionEffectObservation::Interrupted {
                    evidence: Box::new(evidence.clone())
                }
            );
            assert!(!terminal_outcome_observed(&admission, outcome));

            let key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]).verifying_key();
            let receipt = read_outcome_receipt(&root, &admission, &key)
                .unwrap()
                .unwrap();
            let mut changed = receipt.clone();
            let NativeSessionEffectObservation::Interrupted { evidence } =
                &mut changed.outcome.effects
            else {
                panic!("worker death must retain interruption evidence");
            };
            evidence.entries[1].state = NativeEffectWalState::ProviderReturned;
            evidence.completed_effect_count = 2;
            evidence.interrupted_effect_count = 0;
            assert!(changed.verify(&admission, &key).is_err());

            let mut unreaped = outcome.clone();
            unreaped.process = NativeSessionProcessObservation::Unproven;
            assert!(validate_outcome(&admission, &unreaped).is_err());
            let mut panicked = outcome.clone();
            panicked.kind = NativeSessionOutcomeKind::Panicked;
            assert!(validate_outcome(&admission, &panicked).is_err());
        }
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
            panic_evidence: None,
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
    fn capacity_status_and_recovery_do_not_provision_an_absent_store() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("absent").join("runtime-evidence");
        let status = read_native_session_capacity_at(&root).unwrap();
        assert!(!status.store_present);
        assert_eq!(status.retained_sessions, 0);
        assert_eq!(status.reserved_bytes, 0);
        assert_eq!(status.pct_full, 0);
        let recovered = recover_native_session_capacity_at(&root).unwrap();
        assert_eq!(recovered.before, status);
        assert_eq!(recovered.after, status);
        assert_eq!(recovered.recovered_sessions, 0);
        assert!(!recovered.quiescence_certified);
        assert!(!root.parent().unwrap().exists());
    }

    #[test]
    fn explicit_capacity_recovery_preserves_uncertainty_receipts_and_fences() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let first = fixture(&root, 201);
        let second = fixture(&root, 202);
        let pending = fixture(&root, 203);
        let project = first.project_root.clone();
        let first_guard = NativeSessionInventoryGuard::admit(&root, first.clone(), 0).unwrap();
        let second_guard = NativeSessionInventoryGuard::admit(&root, second.clone(), 0).unwrap();
        let mut pending_guard =
            NativeSessionInventoryGuard::admit(&root, pending.clone(), 0).unwrap();
        pending_guard.worker_started();
        let drain = begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert_eq!(drain.checkpoint.pending_sessions, 3);
        let terminal = terminal_outcome();
        let unknown = NativeSessionOutcome {
            observed_at: Utc::now(),
            kind: NativeSessionOutcomeKind::SupervisionIncomplete,
            process: NativeSessionProcessObservation::Unproven,
            containment_empty_observed: false,
            effects: NativeSessionEffectObservation::Unknown,
            panic_evidence: None,
        };
        abandon_after_receipt(&root, first_guard, &terminal);
        abandon_after_receipt(&root, second_guard, &unknown);
        let first_path = outcome_receipt_path(&root, &first.session_nonce);
        let second_path = outcome_receipt_path(&root, &second.session_nonce);
        let first_signed = std::fs::read(&first_path).unwrap();
        let second_signed = std::fs::read(&second_path).unwrap();
        let rows = read_inventory_at(&root, None).unwrap().records;
        let status = read_native_session_capacity_at(&root).unwrap();
        assert_eq!(status.pending_null_outcomes, 3);
        assert_eq!(
            status.reserved_bytes - status.actual_bytes,
            3 * MAX_OUTCOME_BYTES
        );
        assert_eq!(read_inventory_at(&root, None).unwrap().records, rows);

        let recovered = recover_native_session_capacity_at(&root).unwrap();
        assert_eq!(recovered.before, status);
        assert_eq!(recovered.recovered_sessions, 2);
        assert_eq!(recovered.after.retained_sessions, 3);
        assert_eq!(recovered.after.pending_null_outcomes, 1);
        assert!(recovered.reclaimed_reserved_bytes > MAX_OUTCOME_BYTES);
        assert!(!recovered.quiescence_certified);
        let after = read_inventory_at(&root, None).unwrap();
        assert_eq!(after.terminal_sessions, 1);
        assert_eq!(after.unproven_process_sessions, 2);
        assert_eq!(after.unknown_effect_sessions, 2);
        let unresolved = after
            .records
            .iter()
            .find(|record| record.admission.session_nonce == pending.session_nonce)
            .unwrap();
        assert!(unresolved.outcome.is_none());
        assert_eq!(std::fs::read(&first_path).unwrap(), first_signed);
        assert_eq!(std::fs::read(&second_path).unwrap(), second_signed);
        assert!(admission_ticket_at(&root, &project).is_err());
        let repeated = recover_native_session_capacity_at(&root).unwrap();
        assert_eq!(repeated.recovered_sessions, 0);
        assert_eq!(repeated.reclaimed_reserved_bytes, 0);
        assert_eq!(repeated.before, repeated.after);
        assert_eq!(repeated.after, recovered.after);
    }

    #[test]
    fn explicit_capacity_recovery_authenticates_the_entire_batch_before_writing() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let first = fixture(&root, 204);
        let second = fixture(&root, 205);
        let first_guard = NativeSessionInventoryGuard::admit(&root, first.clone(), 0).unwrap();
        let second_guard = NativeSessionInventoryGuard::admit(&root, second.clone(), 0).unwrap();
        abandon_after_receipt(&root, first_guard, &terminal_outcome());
        abandon_after_receipt(&root, second_guard, &terminal_outcome());
        let first_path = outcome_receipt_path(&root, &first.session_nonce);
        let second_path = outcome_receipt_path(&root, &second.session_nonce);
        let second_signed = std::fs::read(&second_path).unwrap();
        std::fs::write(&second_path, std::fs::read(&first_path).unwrap()).unwrap();
        let original = read_inventory_at(&root, None).unwrap().records;
        assert!(recover_native_session_capacity_at(&root).is_err());
        assert_eq!(read_inventory_at(&root, None).unwrap().records, original);
        std::fs::write(&second_path, second_signed).unwrap();
        assert_eq!(
            recover_native_session_capacity_at(&root)
                .unwrap()
                .recovered_sessions,
            2
        );
    }

    #[test]
    fn explicit_capacity_recovery_unblocks_saturation_without_dropping_a_session() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let limit = MAX_RESERVED_BYTES / MAX_OUTCOME_BYTES;
        for index in 0..limit {
            let admission = fixture(&root, u8::try_from(index + 1).unwrap());
            let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
            guard.worker_started();
            guard.finished = true;
        }
        let before = read_inventory_at(&root, None).unwrap().records;
        let error = NativeSessionInventoryGuard::admit(&root, fixture(&root, 210), 0)
            .err()
            .expect("unsigned pending outcomes must retain their full reservation");
        assert!(format!("{error:#}").contains(RECOVER_CAPACITY_COMMAND));
        assert_eq!(
            recover_native_session_capacity_at(&root)
                .unwrap()
                .recovered_sessions,
            0
        );
        assert_eq!(read_inventory_at(&root, None).unwrap().records, before);
        let outcome = terminal_outcome();
        retain_outcome_receipt(&root, &before[0].admission, &outcome).unwrap();
        let recovered = recover_native_session_capacity_at(&root).unwrap();
        assert_eq!(recovered.recovered_sessions, 1);
        assert_eq!(recovered.after.retained_sessions, limit);
        assert_eq!(recovered.after.pending_null_outcomes, limit - 1);
        let next = NativeSessionInventoryGuard::admit(&root, fixture(&root, 211), 0).unwrap();
        let after = read_inventory_at(&root, None).unwrap();
        assert_eq!(after.total_stored_sessions, limit + 1);
        for record in before.iter().skip(1) {
            assert!(after.records.contains(record));
        }
        assert_eq!(after.terminal_sessions, 1);
        assert!(!after.quiescence_certified);
        drop(next);
    }

    #[test]
    fn capacity_status_counts_utf8_bytes_without_decoding_oversized_accounting() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        ensure_runtime_evidence_directory(root.parent().unwrap(), true).unwrap();
        ensure_runtime_evidence_directory(&root, true).unwrap();
        let connection = open_inventory(&root, true).unwrap().unwrap();
        let mut tx = connection.transaction().unwrap();
        tx.execute_with_params(
            "INSERT INTO native_sessions(session_nonce, admission_json, outcome_json)
             VALUES ('accounting-only', ?1, NULL);",
            &[SqliteValue::Text("🦀".to_owned().into())],
        )
        .unwrap();
        let report = capacity_report_in_transaction(&root, &tx).unwrap();
        assert_eq!(report.actual_bytes, 4);
        assert_eq!(report.reserved_bytes, MAX_OUTCOME_BYTES + 4);
        assert_eq!(report.pending_null_outcomes, 1);
        tx.commit().unwrap();
        // Capacity inspection is explicitly accounting, not evidence parsing.
        assert_eq!(read_native_session_capacity_at(&root).unwrap(), report);
        assert!(recover_native_session_capacity_at(&root).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn capacity_commands_refuse_symlinked_evidence_without_touching_targets() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let target = outside.join("sentinel");
        std::fs::write(&target, b"preserve").unwrap();
        let root = temp.path().join("linked-evidence");
        symlink(&outside, &root).unwrap();
        assert!(read_native_session_capacity_at(&root).is_err());
        assert!(recover_native_session_capacity_at(&root).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"preserve");
        assert!(!outside.join(INVENTORY_FILE).exists());
    }

    #[test]
    fn capacity_recovery_repairs_an_oversaturated_projection_without_relaxing_limits() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let limit = MAX_RESERVED_BYTES / MAX_OUTCOME_BYTES;
        for index in 0..=limit {
            let admission = fixture(&root, u8::try_from(index + 1).unwrap());
            let guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
            abandon_after_receipt(&root, guard, &terminal_outcome());
        }
        // Model loss of database projections while the signed observations
        // survive. This is not a claim of successful process cleanup.
        let connection = open_inventory(&root, false).unwrap().unwrap();
        connection
            .execute("UPDATE native_sessions SET outcome_json = NULL;")
            .unwrap();
        let status = read_native_session_capacity_at(&root).unwrap();
        assert!(status.capacity_exceeded);
        assert!(status.reserved_bytes > MAX_RESERVED_BYTES);
        assert!(status.actual_bytes < MAX_RESERVED_BYTES);
        assert!(read_inventory_at(&root, None).is_err());
        let recovered = recover_native_session_capacity_at(&root).unwrap();
        assert_eq!(recovered.before, status);
        assert_eq!(recovered.recovered_sessions, limit + 1);
        assert_eq!(recovered.after.pending_null_outcomes, 0);
        assert!(!recovered.after.capacity_exceeded);
        assert_eq!(recovered.after.max_reserved_bytes, MAX_RESERVED_BYTES);
        assert_eq!(recovered.after.max_retained_sessions, MAX_STORED_SESSIONS);
        let _next = NativeSessionInventoryGuard::admit(&root, fixture(&root, 212), 0).unwrap();
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
    fn admission_recovers_signed_outcomes_before_reservation_exhaustion() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let pending_limit = MAX_RESERVED_BYTES / MAX_OUTCOME_BYTES;
        let mut retained = Vec::new();
        for index in 0..=pending_limit {
            let admission = fixture(&root, u8::try_from(index + 1).unwrap());
            let guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            let outcome = terminal_outcome();
            // Model receipt publication followed by a lost database commit.
            // The next launch must eventually recover these exact observations
            // without a fleet agent, larger budget, or historical row eviction.
            abandon_after_receipt(&root, guard, &outcome);
            let path = outcome_receipt_path(&root, &admission.session_nonce);
            let signed = std::fs::read(&path).unwrap();
            retained.push((admission, outcome, path, signed));
        }
        let report = read_inventory_at(&root, None).unwrap();
        assert_eq!(report.total_stored_sessions, pending_limit + 1);
        assert_eq!(report.terminal_sessions, pending_limit);
        assert_eq!(report.pending_sessions, 1);
        for (index, (admission, outcome, path, signed)) in retained.iter().enumerate() {
            let record = report
                .records
                .iter()
                .find(|record| record.admission.session_nonce == admission.session_nonce)
                .unwrap();
            assert_eq!(&record.admission, admission);
            assert_eq!(
                record.outcome.as_ref(),
                (index < pending_limit).then_some(outcome)
            );
            assert_eq!(&std::fs::read(path).unwrap(), signed);
        }
        // A healthy subsequent admission must not reissue historical evidence.
        let _next = NativeSessionInventoryGuard::admit(&root, fixture(&root, 100), 0).unwrap();
        let after = read_inventory_at(&root, None).unwrap();
        for record in &report.records {
            assert!(after.records.contains(record));
        }
        for (_, _, path, signed) in &retained {
            assert_eq!(&std::fs::read(path).unwrap(), signed);
        }
    }

    #[test]
    fn admission_capacity_recovery_is_atomic_and_preserves_unknown_obligations() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let pending_limit = MAX_RESERVED_BYTES / MAX_OUTCOME_BYTES;
        let mut admissions = Vec::new();
        for index in 0..pending_limit {
            let admission = fixture(&root, u8::try_from(index + 1).unwrap());
            let mut guard =
                NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            guard.worker_started();
            // Neither Drop nor a receipt resolves these deliberately missing
            // supervisor observations. Their full reservation must survive.
            guard.finished = true;
            drop(guard);
            admissions.push(admission);
        }
        let original = read_inventory_at(&root, None).unwrap().records;
        let project = admissions[0].project_root.clone();
        let drain = begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert!(drain.checkpoint.fence_held);
        let next_admission = |marker| {
            let mut admission = fixture(&root, marker);
            // Recovery must not release the old project's fence in order to
            // admit a separately controlled project sharing the evidence store.
            admission.project_root = temp.path().join("other-project");
            admission.entrypoint = admission.project_root.join("index.js");
            admission
        };
        let prospective = next_admission(100);
        let error = NativeSessionInventoryGuard::admit(&root, prospective.clone(), 0)
            .err()
            .expect("missing receipts must retain their reserved capacity");
        assert!(format!("{error:#}").contains("inventory capacity exceeded"));
        assert_eq!(read_inventory_at(&root, None).unwrap().records, original);
        // A receipt surviving a lost row cannot discharge the reservation of
        // the very admission now being retried and make its worker untracked.
        retain_outcome_receipt(&root, &prospective, &terminal_outcome()).unwrap();
        let error = NativeSessionInventoryGuard::admit(&root, prospective, 0)
            .err()
            .expect("a retried admission must retain its own reservation");
        assert!(format!("{error:#}").contains("inventory capacity exceeded"));
        assert_eq!(read_inventory_at(&root, None).unwrap().records, original);

        let unknown = NativeSessionOutcome {
            observed_at: Utc::now(),
            kind: NativeSessionOutcomeKind::SupervisionIncomplete,
            process: NativeSessionProcessObservation::Unproven,
            containment_empty_observed: false,
            effects: NativeSessionEffectObservation::Unknown,
            panic_evidence: None,
        };
        retain_outcome_receipt(&root, &admissions[0], &unknown).unwrap();
        let terminal = terminal_outcome();
        retain_outcome_receipt(&root, &admissions[1], &terminal).unwrap();
        let first_path = outcome_receipt_path(&root, &admissions[0].session_nonce);
        let second_path = outcome_receipt_path(&root, &admissions[1].session_nonce);
        let first_signed = std::fs::read(&first_path).unwrap();
        let second_signed = std::fs::read(&second_path).unwrap();
        // Even a valid signature cannot supply another session's observation.
        // One bad candidate must roll back the complete admission/recovery.
        std::fs::write(&second_path, &first_signed).unwrap();
        assert!(NativeSessionInventoryGuard::admit(&root, next_admission(101), 0).is_err());
        assert_eq!(read_inventory_at(&root, None).unwrap().records, original);
        std::fs::write(&second_path, &second_signed).unwrap();

        let _next = NativeSessionInventoryGuard::admit(&root, next_admission(102), 0).unwrap();
        let recovered = read_inventory_at(&root, None).unwrap();
        assert_eq!(recovered.total_stored_sessions, pending_limit + 1);
        assert_eq!(recovered.pending_sessions, pending_limit - 1);
        assert_eq!(recovered.terminal_sessions, 1);
        assert_eq!(recovered.unknown_effect_sessions, pending_limit);
        assert_eq!(recovered.unproven_process_sessions, pending_limit);
        for (admission, outcome) in [(&admissions[0], &unknown), (&admissions[1], &terminal)] {
            let record = recovered
                .records
                .iter()
                .find(|record| record.admission.session_nonce == admission.session_nonce)
                .unwrap();
            assert_eq!(record.outcome.as_ref(), Some(outcome));
        }
        assert_eq!(std::fs::read(first_path).unwrap(), first_signed);
        assert_eq!(std::fs::read(second_path).unwrap(), second_signed);
        assert!(admission_ticket_at(&root, &project).is_err());
        assert!(!recovered.quiescence_certified);
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
    fn local_control_hint_tracks_committed_fence_generations_and_release() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let admission = fixture(&root, 153);
        let project = admission.project_root.clone();
        let guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        let path = control_hint_path_at(&root, &project).unwrap();
        assert!(!path.exists());
        assert_ne!(
            path,
            control_hint_path_at(&root, &project.join("nested-release")).unwrap()
        );

        let checkpoint = actions(1);
        let held = begin_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap();
        let first = SeqlockControlPage::read_shared_page(&path).unwrap();
        assert_eq!(first.sequence, held.generation * 2);
        assert_eq!(first.active_hold_count, 1);
        assert_eq!(first.action_count, 1);
        assert!(admission_ticket_at(&root, &project).is_err());

        // An operator-writable hint cannot release the real database fence.
        let forged = SeqlockControlPage::new();
        forged.publish(u64::MAX, 0, 0, 0, [0; 32]);
        forged.write_shared_page(&path).unwrap();
        assert!(admission_ticket_at(&root, &project).is_err());
        begin_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap();
        assert_eq!(SeqlockControlPage::read_shared_page(&path).unwrap(), first);

        // The unspawned admission has no worker/effect obligation. Releasing
        // this exact census changes the hint even within the same generation.
        drop(guard);
        let released = finish_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap();
        let second = SeqlockControlPage::read_shared_page(&path).unwrap();
        assert!(released.checkpoint.is_complete());
        assert_eq!(second.sequence, first.sequence);
        assert_eq!(second.active_hold_count, 0);
        assert_ne!(second, first);
        assert_eq!(
            admission_ticket_at(&root, &project).unwrap(),
            held.generation
        );

        let unchanged = std::fs::read(&path).unwrap();
        assert!(begin_drain_at(&root, &project, "node-a", "prod", &actions(0)).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), unchanged);
        let newer = begin_drain_at(&root, &project, "node-a", "prod", &actions(2)).unwrap();
        let third = SeqlockControlPage::read_shared_page(&path).unwrap();
        assert!(newer.generation > held.generation);
        assert!(third.sequence > second.sequence);
        assert_eq!(third.action_count, 2);
        assert_eq!(third.active_hold_count, 1);
    }

    #[test]
    fn local_control_hint_failure_never_undoes_or_ambiguates_committed_fences() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let admission = fixture(&root, 154);
        let project = admission.project_root.clone();
        let guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        let path = control_hint_path_at(&root, &project).unwrap();
        // A directory cannot be atomically replaced by a page. Publication is
        // unavailable, but the already durable state transition still succeeds.
        std::fs::create_dir(&path).unwrap();
        let checkpoint = actions(1);
        let held = begin_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap();
        assert!(held.checkpoint.fence_held);
        assert!(admission_ticket_at(&root, &project).is_err());
        assert!(SeqlockControlPage::read_shared_page(&path).is_err());
        drop(guard);
        let released = finish_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap();
        assert!(released.checkpoint.is_complete());
        assert_eq!(
            admission_ticket_at(&root, &project).unwrap(),
            held.generation
        );
        assert!(path.is_dir());
        assert_eq!(
            std::fs::read_dir(&root)
                .unwrap()
                .filter(|entry| entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("session-control-"))
                .count(),
            1,
            "an unavailable optional hint must not accumulate temporary pages"
        );
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
            attested_checkpoint: None,
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

    fn attest_drain_at(
        root: &Path,
        project: &Path,
        node: &str,
        zone: &str,
        checkpoint: &FleetApplicationCheckpoint,
    ) -> Result<NativeSessionDrainReport> {
        super::attest_drain_at(
            root,
            project,
            node,
            zone,
            checkpoint,
            NativeSessionDrainAttestationMode::Retain,
        )
    }

    fn alter_retained_drain_checkpoint(
        root: &Path,
        project: &Path,
        alter: impl FnOnce(&mut NativeSessionDrainCheckpoint),
    ) {
        let connection = open_inventory(root, false).unwrap().unwrap();
        let mut tx = connection.transaction().unwrap();
        let mut drain = latest_drain(&tx, project).unwrap().unwrap();
        alter(drain.attested_checkpoint.as_mut().unwrap());
        tx.execute_with_params(
            "UPDATE native_session_drains SET state_json = ?1 WHERE drain_id = ?2;",
            &[
                SqliteValue::Text(serde_json::to_string(&drain).unwrap().into()),
                SqliteValue::Text(drain.drain_id.into()),
            ],
        )
        .unwrap();
        tx.commit().unwrap();
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
    fn admission_scope_keys_reject_aliases_and_unbounded_ancestor_walks() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("absent-evidence");
        let project = temp.path().join("project");
        assert_eq!(project_key(&project).unwrap(), project.to_str().unwrap());
        for suffix in ["/./nested", "//nested", "/nested/", "/../other", "/nul\0"] {
            let alias = PathBuf::from(format!("{}{suffix}", project.display()));
            assert!(admission_ticket_at(&root, &alias).is_err(), "{alias:?}");
        }
        let deep = (0..129).fold(project, |path, _| path.join("x"));
        assert!(admission_ticket_at(&root, &deep).is_err());
        assert!(!root.exists());
    }

    #[test]
    fn nested_admission_retains_parent_and_child_maintenance_owners() {
        for parent_first in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let mut admission = fixture(&root, 191);
            let parent = admission.project_root.clone();
            let child = parent.join("nested/child");
            admission.project_root = child.clone();
            admission.entrypoint = child.join("index.js");
            let nonce = admission.session_nonce.clone();
            let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
            guard.worker_started();
            let parent_history = vec![maintenance_action("parent-held", None)];
            let child_history = vec![maintenance_action("child-held", None)];
            let parent_checkpoint = fleet_application_checkpoint(&parent_history, "prod").unwrap();
            let child_checkpoint = fleet_application_checkpoint(&child_history, "prod").unwrap();
            for (project, node, checkpoint, history) in [
                (&parent, "parent-node", &parent_checkpoint, &parent_history),
                (&child, "child-node", &child_checkpoint, &child_history),
            ] {
                let drain =
                    super::begin_drain_at(&root, project, node, "prod", checkpoint, history)
                        .unwrap();
                assert_eq!(drain.session_nonces, vec![nonce.clone()]);
                assert_eq!(drain.checkpoint.pending_sessions, 1);
            }
            assert!(admission_ticket_at(&root, &child).is_err());
            guard.worker_reaped();
            guard.finish(
                NativeSessionOutcomeKind::ControlStopped,
                successful_ledger_observation(),
            );
            for (project, node, checkpoint) in [
                (&parent, "parent-node", &parent_checkpoint),
                (&child, "child-node", &child_checkpoint),
            ] {
                let held = finish_drain_at(&root, project, node, "prod", checkpoint).unwrap();
                assert_eq!(held.checkpoint.terminal_sessions, 1);
                assert!(held.checkpoint.fence_held);
            }
            let parent_owner = (&parent, "parent-node", "parent-held", "parent-resumed");
            let child_owner = (&child, "child-node", "child-held", "child-resumed");
            let resume_order = if parent_first {
                [parent_owner, child_owner]
            } else {
                [child_owner, parent_owner]
            };
            let mut enclosing_revision = 0;
            for (index, (project, node, hold_id, resume_id)) in resume_order.into_iter().enumerate()
            {
                let history = vec![
                    maintenance_action(hold_id, None),
                    maintenance_action(resume_id, Some(hold_id)),
                ];
                let checkpoint = fleet_application_checkpoint(&history, "prod").unwrap();
                super::begin_drain_at(&root, project, node, "prod", &checkpoint, &history).unwrap();
                assert!(
                    admission_ticket_at(&root, &child).is_err(),
                    "publishing {node}'s resume must not skip successful action application"
                );
                let resumed = finish_drain_at(&root, project, node, "prod", &checkpoint).unwrap();
                assert!(resumed.checkpoint.is_complete());
                assert!(resumed.maintenance_hold_ids.is_empty());
                enclosing_revision += resumed.generation;
                if index == 0 {
                    assert!(
                        admission_ticket_at(&root, &child).is_err(),
                        "resuming {node} first must retain the other owner's independent hold"
                    );
                }
            }
            let ticket = admission_ticket_at(&root, &child).unwrap();
            assert_eq!(ticket, enclosing_revision);
            let mut fresh = fixture(&root, 192);
            fresh.project_root = child.clone();
            fresh.entrypoint = child.join("index.js");
            let mut fresh_guard = NativeSessionInventoryGuard::admit(&root, fresh, ticket).unwrap();
            fresh_guard.worker_started();
            assert_eq!(
                read_inventory_at(&root, Some(&child))
                    .unwrap()
                    .pending_sessions,
                1
            );
            fresh_guard.worker_reaped();
            fresh_guard.finish(
                NativeSessionOutcomeKind::Completed,
                successful_ledger_observation(),
            );
        }
    }

    #[test]
    fn nested_admission_rejects_parent_fence_and_completed_cycle() {
        for finish_parent_before_admission in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let mut initial = fixture(&root, 193);
            let parent = initial.project_root.clone();
            let child = parent.join("nested");
            initial.project_root = child.clone();
            initial.entrypoint = child.join("index.js");
            drop(NativeSessionInventoryGuard::admit(&root, initial, 0).unwrap());
            // A max-generation ticket would miss the parent's later 0 -> 1.
            for action_count in 1..=3 {
                begin_drain_at(&root, &child, "child-node", "prod", &actions(action_count))
                    .unwrap();
                finish_drain_at(&root, &child, "child-node", "prod", &actions(action_count))
                    .unwrap();
            }
            let old_ticket = admission_ticket_at(&root, &child).unwrap();
            assert_eq!(old_ticket, 3);
            let parent_drain =
                begin_drain_at(&root, &parent, "parent-node", "prod", &actions(1)).unwrap();
            assert_eq!(parent_drain.checkpoint.admitted_sessions, 1);
            if finish_parent_before_admission {
                assert!(
                    finish_drain_at(&root, &parent, "parent-node", "prod", &actions(1))
                        .unwrap()
                        .checkpoint
                        .is_complete()
                );
                assert_eq!(admission_ticket_at(&root, &child).unwrap(), 4);
            } else {
                assert!(admission_ticket_at(&root, &child).is_err());
            }
            let mut stale = fixture(&root, 194);
            stale.project_root = child.clone();
            stale.entrypoint = child.join("index.js");
            let error = NativeSessionInventoryGuard::admit(&root, stale.clone(), old_ticket)
                .err()
                .unwrap();
            assert!(format!("{error:#}").contains("drain fence"));
            let key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]).verifying_key();
            let refused = read_outcome_receipt(&root, &stale, &key).unwrap().unwrap();
            assert_eq!(
                refused.outcome.process,
                NativeSessionProcessObservation::NotSpawned
            );
            assert_eq!(
                refused.outcome.effects,
                NativeSessionEffectObservation::NotStarted
            );
            let finished =
                finish_drain_at(&root, &parent, "parent-node", "prod", &actions(1)).unwrap();
            assert!(
                finished.checkpoint.is_complete(),
                "a signed never-spawned refusal must not poison the parent's original census"
            );
            assert_eq!(finished.session_nonces, parent_drain.session_nonces);
            let ticket = admission_ticket_at(&root, &child).unwrap();
            assert_eq!(ticket, 4);
            let mut fresh = fixture(&root, 195);
            fresh.project_root = child.clone();
            fresh.entrypoint = child.join("index.js");
            drop(NativeSessionInventoryGuard::admit(&root, fresh, ticket).unwrap());
        }
    }

    #[test]
    fn ancestor_census_retains_operator_descendants_without_prefix_siblings() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let parent = temp.path().join("operator");
        let operator = parent.join("tenant");
        let admission = operator_fixture(&root, 196, &operator, 0);
        let nonce = admission.session_nonce.clone();
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        guard.worker_started();
        let sibling = temp.path().join("operator-other");
        let mut unrelated = fixture(&root, 197);
        unrelated.project_root = sibling.clone();
        unrelated.entrypoint = sibling.join("index.js");
        let mut unrelated_guard = NativeSessionInventoryGuard::admit(&root, unrelated, 0).unwrap();
        unrelated_guard.worker_started();
        for scope in [&parent, &operator] {
            let inventory = read_inventory_at(&root, Some(scope)).unwrap();
            assert_eq!(inventory.pending_sessions, 1);
            assert_eq!(inventory.records[0].admission.session_nonce, nonce);
        }
        let started = begin_drain_at(&root, &parent, "operator-node", "prod", &actions(1)).unwrap();
        assert_eq!(started.session_nonces, vec![nonce]);
        assert_eq!(started.checkpoint.pending_sessions, 1);
        assert!(admission_ticket_at(&root, &operator).is_err());
        assert_eq!(admission_ticket_at(&root, &sibling).unwrap(), 0);
        guard.worker_reaped();
        guard.finish(
            NativeSessionOutcomeKind::ControlStopped,
            successful_ledger_observation(),
        );
        let completed =
            finish_drain_at(&root, &parent, "operator-node", "prod", &actions(1)).unwrap();
        assert!(completed.checkpoint.is_complete());
        assert_eq!(completed.checkpoint.terminal_sessions, 1);
        assert_eq!(
            read_inventory_at(&root, Some(&sibling))
                .unwrap()
                .pending_sessions,
            1
        );
        let stale = operator_fixture(&root, 198, &operator, 0);
        assert!(NativeSessionInventoryGuard::admit(&root, stale.clone(), 0).is_err());
        let key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]).verifying_key();
        let refused = read_outcome_receipt(&root, &stale, &key).unwrap().unwrap();
        assert_eq!(
            refused.outcome.process,
            NativeSessionProcessObservation::NotSpawned
        );
        let fresh = operator_fixture(&root, 199, &operator, completed.generation);
        drop(NativeSessionInventoryGuard::admit(&root, fresh, 0).unwrap());
        unrelated_guard.worker_reaped();
        unrelated_guard.finish(
            NativeSessionOutcomeKind::ControlStopped,
            successful_ledger_observation(),
        );
    }

    #[test]
    fn held_ancestor_census_cannot_hide_a_previously_omitted_descendant() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        drop(NativeSessionInventoryGuard::admit(&root, fixture(&root, 200), 0).unwrap());
        let parent = temp.path().join("held-parent");
        let history = vec![maintenance_action("ancestor-held", None)];
        let checkpoint = fleet_application_checkpoint(&history, "prod").unwrap();
        super::begin_drain_at(&root, &parent, "parent-node", "prod", &checkpoint, &history)
            .unwrap();
        finish_drain_at(&root, &parent, "parent-node", "prod", &checkpoint).unwrap();
        let original = attest_drain_at(&root, &parent, "parent-node", "prod", &checkpoint).unwrap();
        assert_eq!(original.checkpoint.admitted_sessions, 0);
        // Model an authenticated pre-upgrade admission omitted by the old
        // exact-root census. Never use new admission to bypass a held fence.
        let mut omitted = fixture(&root, 201);
        omitted.project_root = parent.join("nested");
        omitted.entrypoint = omitted.project_root.join("index.js");
        retain_admission_receipt(&root, &omitted).unwrap();
        let connection = open_inventory(&root, false).unwrap().unwrap();
        let mut tx = connection.transaction().unwrap();
        tx.execute_with_params(
            "INSERT INTO native_sessions(session_nonce, admission_json, outcome_json)
             VALUES (?1, ?2, NULL);",
            &[
                SqliteValue::Text(omitted.session_nonce.clone().into()),
                SqliteValue::Text(serde_json::to_string(&omitted).unwrap().into()),
            ],
        )
        .unwrap();
        tx.commit().unwrap();
        assert_eq!(
            read_inventory_at(&root, Some(&parent))
                .unwrap()
                .pending_sessions,
            1
        );
        assert!(
            super::begin_drain_at(&root, &parent, "parent-node", "prod", &checkpoint, &history,)
                .is_err()
        );
        assert!(finish_drain_at(&root, &parent, "parent-node", "prod", &checkpoint).is_err());
        assert!(attest_drain_at(&root, &parent, "parent-node", "prod", &checkpoint).is_err());
        assert!(admission_ticket_at(&root, &omitted.project_root).is_err());
        let mut tx = connection.transaction().unwrap();
        let retained = latest_drain(&tx, &parent).unwrap().unwrap();
        assert_eq!(retained.session_nonces, original.session_nonces);
        assert_eq!(retained.attested_checkpoint, Some(original.checkpoint));
        tx.commit().unwrap();
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
        super::begin_drain_at(&root, &project, "node-a", "prod", &checkpoint, &history).unwrap();
        let held = finish_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap();
        assert!(held.checkpoint.fence_held);
        assert_eq!(held.maintenance_hold_ids.len(), 2);
        // A nested input has no exact drain row of its own. Both native and
        // reference admission must retain the ancestor's operator fences.
        assert!(admission_ticket_at(&root, &nested).is_err());
        assert!(enforce_reference_admission_at(&root, &project).is_err());
        assert!(enforce_reference_admission_at(&root, &nested).is_err());
        enforce_reference_admission_at(&root, &unrelated).unwrap();

        history.push(maintenance_action(
            "reference-resume-a",
            Some("reference-hold-a"),
        ));
        let checkpoint = fleet_application_checkpoint(&history, "prod").unwrap();
        super::begin_drain_at(&root, &project, "node-a", "prod", &checkpoint, &history).unwrap();
        let one_owner = finish_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap();
        assert_eq!(one_owner.maintenance_hold_ids, vec!["reference-hold-b"]);
        assert!(enforce_reference_admission_at(&root, &nested).is_err());

        history.push(maintenance_action(
            "reference-resume-b",
            Some("reference-hold-b"),
        ));
        let checkpoint = fleet_application_checkpoint(&history, "prod").unwrap();
        super::begin_drain_at(&root, &project, "node-a", "prod", &checkpoint, &history).unwrap();
        assert!(
            enforce_reference_admission_at(&root, &nested).is_err(),
            "publishing a resume cannot skip successful action application"
        );
        let resumed = finish_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap();
        assert!(resumed.checkpoint.is_complete());
        enforce_reference_admission_at(&root, &project).unwrap();
        enforce_reference_admission_at(&root, &nested).unwrap();
        assert_eq!(
            admission_ticket_at(&root, &nested).unwrap(),
            resumed.generation
        );
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
        let drain = super::begin_drain_at(&root, &project, "node-a", "prod", &checkpoint, &history)
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
        let error = enforce_reference_admission_at(&root, &project.join("nested")).unwrap_err();
        assert!(format!("{error:#}").contains("decode native-session inventory record"));
        let error = admission_ticket_at(&root, &project.join("nested")).unwrap_err();
        assert!(format!("{error:#}").contains("decode native-session inventory record"));
    }

    #[test]
    fn reference_admission_does_not_initialize_an_absent_inventory() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("absent-evidence");
        enforce_reference_admission_at(&root, &temp.path().join("project")).unwrap();
        assert_eq!(
            admission_ticket_at(&root, &temp.path().join("project")).unwrap(),
            0
        );
        assert!(!root.exists());
        assert!(enforce_reference_admission_at(&root, Path::new("relative/project")).is_err());
        assert!(admission_ticket_at(&root, Path::new("relative/project")).is_err());
        assert!(admission_ticket_at(&root, &temp.path().join("project/../other")).is_err());
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
            NativeSessionOutcomeKind::ExecutionFailed,
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
            panic_evidence: None,
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
            panic_evidence: None,
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
            panic_evidence: None,
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
        finish_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert_eq!(
            attest_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap(),
            signed,
            "an unchanged indeterminate obligation retains its exact signed checkpoint"
        );
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
        let signed = attest_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap();
        assert!(signed.checkpoint.supervisor_attestation.is_some());
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
        {
            let connection = open_inventory(&root, false).unwrap().unwrap();
            let mut tx = connection.transaction().unwrap();
            let retained = latest_drain(&tx, &project).unwrap().unwrap();
            assert_eq!(
                retained.attested_checkpoint.as_ref(),
                Some(&before.checkpoint)
            );
            tx.commit().unwrap();
        }
        assert_eq!(
            attest_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap(),
            before,
            "reopening the inventory must preserve the full signed completed checkpoint"
        );
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
        assert_eq!(during, before);
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
        assert_eq!(historical, before);
        let next = begin_drain_at(&root, &project, "node-a", "prod", &actions(2)).unwrap();
        assert_eq!(next.checkpoint.admitted_sessions, 2);
        finish_drain_at(&root, &project, "node-a", "prod", &actions(2)).unwrap();
        let next = attest_drain_at(&root, &project, "node-a", "prod", &actions(2)).unwrap();
        assert!(next.checkpoint.is_complete());
        assert_eq!(next.generation, before.generation + 1);
        assert_ne!(next.drain_id, before.drain_id);
        assert_ne!(
            next.checkpoint.supervisor_attestation,
            before.checkpoint.supervisor_attestation
        );
        assert_eq!(
            attest_drain_at(&root, &project, "node-a", "prod", &actions(2)).unwrap(),
            next
        );
    }

    #[test]
    fn empty_action_checkpoint_retains_its_signed_empty_population() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 180);
        let project = admission.project_root.clone();
        drop(NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap());
        begin_drain_at(&root, &project, "node-a", "prod", &actions(0)).unwrap();
        finish_drain_at(&root, &project, "node-a", "prod", &actions(0)).unwrap();
        let first = attest_drain_at(&root, &project, "node-a", "prod", &actions(0)).unwrap();
        assert!(first.checkpoint.is_complete());
        assert_eq!(first.checkpoint.admitted_sessions, 0);
        assert!(first.session_nonces.is_empty());
        first
            .checkpoint
            .supervisor_attestation
            .as_ref()
            .unwrap()
            .verify(
                &first.checkpoint,
                "node-a",
                "prod",
                &ed25519_dalek::SigningKey::from_bytes(&[17; 32]).verifying_key(),
            )
            .unwrap();
        begin_drain_at(&root, &project, "node-a", "prod", &actions(0)).unwrap();
        finish_drain_at(&root, &project, "node-a", "prod", &actions(0)).unwrap();
        assert_eq!(
            attest_drain_at(&root, &project, "node-a", "prod", &actions(0)).unwrap(),
            first
        );
    }

    #[test]
    fn changed_pending_drain_replaces_its_attestation_only_after_real_completion() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 181);
        let project = admission.project_root.clone();
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        guard.worker_started();
        begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        finish_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        let pending = attest_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert_eq!(pending.checkpoint.pending_sessions, 1);
        assert!(pending.checkpoint.fence_held);
        assert_eq!(
            attest_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap(),
            pending
        );
        guard.worker_reaped();
        guard.finish(
            NativeSessionOutcomeKind::ControlStopped,
            successful_ledger_observation(),
        );
        finish_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        let completed = attest_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert!(completed.checkpoint.is_complete());
        assert_eq!(completed.checkpoint.terminal_sessions, 1);
        assert_eq!(completed.drain_id, pending.drain_id);
        assert_eq!(completed.generation, pending.generation);
        assert_eq!(completed.session_nonces, pending.session_nonces);
        assert_ne!(
            completed.checkpoint.supervisor_attestation,
            pending.checkpoint.supervisor_attestation
        );
        assert_eq!(
            attest_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap(),
            completed
        );
    }

    #[test]
    fn fresh_transport_observation_preserves_expired_retained_attestation() {
        use ed25519_dalek::Signer as _;

        for maintenance in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let admission = fixture(&root, 182);
            let project = admission.project_root.clone();
            drop(NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap());
            let history = if maintenance {
                vec![maintenance_action("refresh-held", None)]
            } else {
                action_history(1)
            };
            let checkpoint = fleet_application_checkpoint(&history, "prod").unwrap();
            super::begin_drain_at(&root, &project, "node-a", "prod", &checkpoint, &history)
                .unwrap();
            finish_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap();
            attest_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap();
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
            alter_retained_drain_checkpoint(&root, &project, |cached| {
                let attestation = cached.supervisor_attestation.as_mut().unwrap();
                attestation.observed_at = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
                attestation.signature_hex = hex::encode(
                    signing_key
                        .sign(&attestation.signing_payload().unwrap())
                        .to_bytes(),
                );
            });
            let retained = attest_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap();
            let old = retained.checkpoint.supervisor_attestation.as_ref().unwrap();
            old.verify(
                &retained.checkpoint,
                "node-a",
                "prod",
                &signing_key.verifying_key(),
            )
            .unwrap();
            assert!(old.validate_freshness(Utc::now()).is_err());
            assert_eq!(
                attest_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap(),
                retained,
                "elapsed time must not rewrite a retained observation"
            );
            let refreshed = super::attest_drain_at(
                &root,
                &project,
                "node-a",
                "prod",
                &checkpoint,
                NativeSessionDrainAttestationMode::Refresh,
            )
            .unwrap();
            let fresh = refreshed
                .checkpoint
                .supervisor_attestation
                .as_ref()
                .unwrap();
            fresh
                .verify(
                    &refreshed.checkpoint,
                    "node-a",
                    "prod",
                    &signing_key.verifying_key(),
                )
                .unwrap();
            fresh.validate_freshness(Utc::now()).unwrap();
            fresh.validate_successor_of(old).unwrap();
            assert!(fresh.observed_at > old.observed_at);
            assert_ne!(fresh.signature_hex, old.signature_hex);
            let mut refreshed_accounting = refreshed;
            refreshed_accounting.checkpoint.supervisor_attestation =
                retained.checkpoint.supervisor_attestation.clone();
            assert_eq!(refreshed_accounting, retained);
            assert_eq!(
                attest_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap(),
                retained,
                "a transport refresh must not replace the retained historical signature"
            );
        }
    }

    #[test]
    fn corrupt_or_foreign_cached_attestation_cannot_be_reused_or_resigned() {
        use ed25519_dalek::Signer as _;

        for mutation in 0..5 {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("evidence");
            let admission = fixture(&root, 183);
            let project = admission.project_root.clone();
            let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
            guard.worker_started();
            begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
            finish_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
            attest_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
            alter_retained_drain_checkpoint(&root, &project, |cached| {
                if mutation == 0 {
                    cached.supervisor_attestation = None;
                    return;
                }
                let attestation = cached.supervisor_attestation.as_mut().unwrap();
                match mutation {
                    1 => attestation.signature_hex = "0".repeat(128),
                    2 => attestation.drain_id = uuid::Uuid::now_v7().to_string(),
                    3 => attestation.generation += 1,
                    _ => attestation.project_root_sha256 = "c".repeat(64),
                }
                if mutation >= 2 {
                    // A valid signature from the same product root still
                    // cannot substitute another local drain or project.
                    let key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
                    attestation.signature_hex =
                        hex::encode(key.sign(&attestation.signing_payload().unwrap()).to_bytes());
                    cached
                        .supervisor_attestation
                        .as_ref()
                        .unwrap()
                        .verify(cached, "node-a", "prod", &key.verifying_key())
                        .unwrap();
                }
            });
            for mode in [
                NativeSessionDrainAttestationMode::Retain,
                NativeSessionDrainAttestationMode::Refresh,
            ] {
                assert!(
                    super::attest_drain_at(&root, &project, "node-a", "prod", &actions(1), mode)
                        .is_err(),
                    "cached mutation {mutation} must fail with unchanged accounting"
                );
            }
            guard.worker_reaped();
            guard.finish(
                NativeSessionOutcomeKind::ControlStopped,
                successful_ledger_observation(),
            );
            for mode in [
                NativeSessionDrainAttestationMode::Retain,
                NativeSessionDrainAttestationMode::Refresh,
            ] {
                assert!(
                    super::attest_drain_at(&root, &project, "node-a", "prod", &actions(1), mode)
                        .is_err(),
                    "changed accounting must not launder cached mutation {mutation}"
                );
            }
        }
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
            panic_evidence: None,
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
            panic_evidence: None,
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
            panic_evidence: None,
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
            panic_evidence: None,
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

    #[test]
    fn capacity_error_includes_actionable_fix_command_and_status_succeeds() {
        let err = check_reservation_usage(
            50,
            MAX_RESERVED_BYTES + 1,
            MAX_STORED_SESSIONS,
            MAX_RESERVED_BYTES,
        )
        .expect_err("saturated reservation must fail closed");
        let msg = err.to_string();
        assert!(msg.contains("native-session inventory capacity exceeded"));
        assert!(msg.contains("inspect_command=`franken-node ops session-inventory status --json`"));
        assert!(msg.contains("fix_command=`franken-node ops session-inventory recover --json`"));

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let empty = inspect_native_session_inventory_status_at(&root).unwrap();
        assert!(!empty.database_present);
        assert_eq!(empty.retained_sessions, 0);
        assert!(!empty.admission_blocked);
    }

    fn compaction_request(
        archive_dir: Option<PathBuf>,
        finalize_orphaned_pending: bool,
    ) -> NativeSessionInventoryCompactRequest {
        NativeSessionInventoryCompactRequest {
            archive_dir,
            max_sessions_to_archive: None,
            finalize_orphaned_pending,
            min_pending_age_secs: 0,
            confirm: finalize_orphaned_pending,
            operator_id: Some("compaction-regression".to_owned()),
            reason: Some("preserve supervisor and fleet ownership".to_owned()),
        }
    }

    fn clean_compaction_ledger_observation() -> NativeSessionEffectObservation {
        NativeSessionEffectObservation::FinalLedgerObserved {
            effect_count: 1,
            allowed_count: 1,
            denied_count: 0,
            failed_count: 0,
            chain_head_hash: format!("sha256:{}", "a".repeat(64)),
            ledger_sha256: "b".repeat(64),
        }
    }

    #[cfg(unix)]
    struct PendingSupervisorProcess(std::process::Child);

    #[cfg(unix)]
    impl Drop for PendingSupervisorProcess {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[cfg(unix)]
    #[test]
    fn compaction_pending_supervisor_child() {
        use std::io::Read as _;

        let Some(root) = std::env::var_os("FRANKEN_NODE_COMPACTION_CHILD_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        let admission = fixture(&root, 41);
        let nonce = admission.session_nonce.clone();
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        guard.worker_started();
        let ready = root.join("compaction-child-ready");
        let pending = ready.with_extension("pending");
        std::fs::write(&pending, nonce.as_bytes()).unwrap();
        std::fs::rename(&pending, &ready).unwrap();
        let mut byte = [0_u8];
        std::io::stdin().read_exact(&mut byte).unwrap();
        panic!("supervisor test child must be killed without running guard cleanup");
    }

    #[cfg(unix)]
    fn spawn_pending_supervisor(root: &Path) -> (PendingSupervisorProcess, String) {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        let module = module_path!().split_once("::").unwrap().1;
        let test = format!("{module}::compaction_pending_supervisor_child");
        let mut child = PendingSupervisorProcess(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &test, "--nocapture"])
                .env("FRANKEN_NODE_COMPACTION_CHILD_ROOT", root)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let ready = root.join("compaction-child-ready");
        let deadline = Instant::now() + Duration::from_secs(15);
        while !ready.exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "supervisor child exited without retaining its admission and lease"
            );
            assert!(
                Instant::now() < deadline,
                "supervisor child did not become ready"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let nonce = std::fs::read_to_string(&ready).unwrap();
        assert_eq!(uuid::Uuid::parse_str(&nonce).unwrap().to_string(), nonce);
        (child, nonce)
    }

    #[cfg(unix)]
    #[test]
    fn compact_preserves_live_and_deferred_supervisors_until_real_outcome_persistence() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let admission = fixture(&root, 81);
        let nonce = admission.session_nonce.clone();
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        guard.worker_started();
        let record_path = admission_record_path(&root, &nonce);
        let lease_path = supervisor_lease::path(&root, &nonce);
        let original_admission = std::fs::read(&record_path).unwrap();
        let original_lease = std::fs::read(&lease_path).unwrap();
        let request = compaction_request(None, true);
        let before = inspect_native_session_inventory_status_at(&root).unwrap();
        let live = compact_native_session_inventory_at(&root, &request).unwrap();
        assert_eq!(live.finalized_orphaned_pending, 0);
        assert_eq!(live.after.pending_null_outcomes, 1);
        assert_eq!(live.after.reserved_bytes, before.reserved_bytes);
        assert!(!outcome_receipt_path(&root, &nonce).exists());
        assert_eq!(std::fs::read(&record_path).unwrap(), original_admission);
        assert_eq!(std::fs::read(&lease_path).unwrap(), original_lease);

        guard.worker_reaped();
        let finalizer = DeferredNativeSessionFinalizer::new(
            guard,
            NativeSessionOutcomeKind::Completed,
            clean_compaction_ledger_observation(),
        );
        let deferred = compact_native_session_inventory_at(&root, &request).unwrap();
        assert_eq!(deferred.finalized_orphaned_pending, 0);
        assert_eq!(deferred.after.reserved_bytes, before.reserved_bytes);
        finalizer.finalize();
        let inventory = read_inventory_at(&root, None).unwrap();
        let outcome = inventory.records[0].outcome.as_ref().unwrap();
        assert_eq!(outcome.kind, NativeSessionOutcomeKind::Completed);
        assert_eq!(
            outcome.process,
            NativeSessionProcessObservation::WorkerReaped
        );
        assert_eq!(
            export_native_session_forensics_at(&root, &nonce)
                .unwrap()
                .verification
                .outcome_kind,
            "completed",
        );
        let archived = compact_native_session_inventory_at(
            &root,
            &compaction_request(Some(temp.path().join("archive")), false),
        )
        .unwrap();
        assert_eq!(archived.archived_clean_sessions, 1);
        assert!(
            !lease_path.exists(),
            "retirement must also reclaim the ownership sidecar"
        );
    }

    #[cfg(unix)]
    #[test]
    fn compact_recovers_a_live_supervisors_receipt_without_archiving_its_admission() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let admission = fixture(&root, 87);
        let nonce = admission.session_nonce.clone();
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        guard.worker_reaped();
        let outcome = NativeSessionOutcome {
            observed_at: Utc::now(),
            kind: NativeSessionOutcomeKind::Completed,
            process: NativeSessionProcessObservation::WorkerReaped,
            containment_empty_observed: false,
            effects: clean_compaction_ledger_observation(),
            panic_evidence: None,
        };
        // Stage the real publication boundary: the signed observation exists,
        // while its actual guard has not yet committed the database projection.
        retain_outcome_receipt(&root, &admission, &outcome).unwrap();
        let receipt_path = outcome_receipt_path(&root, &nonce);
        let original_receipt = std::fs::read(&receipt_path).unwrap();
        let request = compaction_request(Some(temp.path().join("archive")), true);
        let live = compact_native_session_inventory_at(&root, &request).unwrap();
        assert_eq!(live.recovered_signed_outcomes, 1);
        assert_eq!(live.finalized_orphaned_pending, 0);
        assert_eq!(live.archived_clean_sessions, 0);
        assert_eq!(live.after.retained_sessions, 1);
        assert_eq!(std::fs::read(&receipt_path).unwrap(), original_receipt);
        assert!(admission_record_path(&root, &nonce).exists());
        assert_eq!(
            read_inventory_at(&root, None).unwrap().records[0].outcome,
            Some(outcome.clone()),
        );

        // Complete that same observation through the production persistence
        // method. Do not synthesize a newer timestamp or claim a process crash.
        guard.persist_outcome(&outcome).unwrap();
        guard.finished = true;
        drop(guard);
        let archived = compact_native_session_inventory_at(&root, &request).unwrap();
        assert_eq!(archived.archived_clean_sessions, 1);
        assert!(!supervisor_lease::path(&root, &nonce).exists());
    }

    #[cfg(unix)]
    #[test]
    fn compact_preserves_pending_admissions_without_valid_ownership_evidence() {
        for mutation in ["missing", "malformed", "replacement"] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("runtime-evidence");
            let admission = fixture(&root, 82);
            let nonce = admission.session_nonce.clone();
            let mut guard =
                NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
            // Model a lost projection owner without publishing an outcome.
            // Real abrupt-process lock release is exercised by the child test.
            guard.finished = true;
            drop(guard);
            let lease_path = supervisor_lease::path(&root, &nonce);
            let original = std::fs::read(&lease_path).unwrap();
            match mutation {
                "missing" => {
                    std::fs::rename(&lease_path, lease_path.with_extension("retained")).unwrap();
                }
                "malformed" => std::fs::write(&lease_path, b"{}").unwrap(),
                "replacement" => {
                    std::fs::rename(&lease_path, lease_path.with_extension("retained")).unwrap();
                    create_new_runtime_evidence_private_file(&lease_path, &original).unwrap();
                }
                _ => unreachable!(),
            }
            let result =
                compact_native_session_inventory_at(&root, &compaction_request(None, true));
            if mutation == "missing" {
                assert_eq!(result.unwrap().finalized_orphaned_pending, 0);
                assert!(
                    !lease_path.exists(),
                    "compaction must not mint missing ownership evidence"
                );
            } else {
                assert!(result.is_err(), "{mutation} ownership must fail closed");
            }
            let retained = read_inventory_at(&root, None).unwrap();
            assert_eq!(retained.records[0].admission, admission);
            assert!(retained.records[0].outcome.is_none());
            assert!(!outcome_receipt_path(&root, &nonce).exists());
            assert_eq!(
                inspect_native_session_inventory_status_at(&root)
                    .unwrap()
                    .pending_phantom_reserved_bytes,
                MAX_OUTCOME_BYTES,
            );
        }
    }

    #[test]
    fn compact_preserves_held_census_evidence_and_reclaims_after_explicit_resume() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let held_admission = fixture(&root, 83);
        let project = held_admission.project_root.clone();
        let nonce = held_admission.session_nonce.clone();
        let mut owner = NativeSessionInventoryGuard::admit(&root, held_admission, 0).unwrap();
        owner.worker_reaped();
        owner.finish(
            NativeSessionOutcomeKind::Completed,
            clean_compaction_ledger_observation(),
        );
        let original_receipt = std::fs::read(outcome_receipt_path(&root, &nonce)).unwrap();
        let mut history = vec![maintenance_action("archive-hold", None)];
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
        assert!(held.checkpoint.fence_held);
        assert_eq!(held.checkpoint.terminal_sessions, 1);

        let mut unrelated = fixture(&root, 84);
        unrelated.project_root = temp.path().join("unrelated-project");
        unrelated.entrypoint = unrelated.project_root.join("index.js");
        let unrelated_nonce = unrelated.session_nonce.clone();
        let mut other = NativeSessionInventoryGuard::admit(&root, unrelated, 0).unwrap();
        other.worker_reaped();
        other.finish(
            NativeSessionOutcomeKind::Completed,
            clean_compaction_ledger_observation(),
        );
        let request = compaction_request(Some(temp.path().join("archive")), false);
        let compacted = compact_native_session_inventory_at(&root, &request).unwrap();
        assert_eq!(compacted.archived_clean_sessions, 1);
        let archive: NativeSessionColdArchiveBundle =
            serde_json::from_slice(&std::fs::read(compacted.archive_path.unwrap()).unwrap())
                .unwrap();
        assert_eq!(archive.entries[0].session_nonce, unrelated_nonce);
        let remaining = read_inventory_at(&root, None).unwrap();
        assert_eq!(remaining.records.len(), 1);
        assert_eq!(remaining.records[0].admission.session_nonce, nonce);
        assert_eq!(
            std::fs::read(outcome_receipt_path(&root, &nonce)).unwrap(),
            original_receipt,
        );
        let still_held =
            finish_drain_at(&root, &project, "node-a", "prod", &held_checkpoint).unwrap();
        assert_eq!(still_held, held);
        assert_eq!(
            attest_drain_at(&root, &project, "node-a", "prod", &held_checkpoint)
                .unwrap()
                .checkpoint
                .terminal_sessions,
            1,
        );

        history.push(maintenance_action("archive-resume", Some("archive-hold")));
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
        assert!(resumed.checkpoint.is_complete());
        assert!(resumed.generation > held.generation);
        // The older generation still records its original hold; it must not
        // permanently pin rows once the latest census has explicitly resumed.
        let reclaimed = compact_native_session_inventory_at(&root, &request).unwrap();
        assert_eq!(reclaimed.archived_clean_sessions, 1);
        assert_eq!(reclaimed.after.retained_sessions, 0);
        let fresh = fixture(&root, 85);
        drop(NativeSessionInventoryGuard::admit(&root, fresh, resumed.generation).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn compact_does_not_finalize_an_orphan_still_owned_by_a_fleet_census() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let admission = fixture(&root, 86);
        let project = admission.project_root.clone();
        let nonce = admission.session_nonce.clone();
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        guard.worker_started();
        let held = begin_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert!(held.checkpoint.fence_held);
        // Release this fixture's owner without inventing a terminal observation.
        guard.finished = true;
        drop(guard);
        let report =
            compact_native_session_inventory_at(&root, &compaction_request(None, true)).unwrap();
        assert_eq!(report.finalized_orphaned_pending, 0);
        assert_eq!(report.after.pending_null_outcomes, 1);
        assert_eq!(
            report.after.pending_phantom_reserved_bytes,
            MAX_OUTCOME_BYTES
        );
        assert!(!outcome_receipt_path(&root, &nonce).exists());
        let retained = finish_drain_at(&root, &project, "node-a", "prod", &actions(1)).unwrap();
        assert!(retained.checkpoint.fence_held);
        assert_eq!(retained.checkpoint.pending_sessions, 1);
    }

    #[cfg(unix)]
    #[test]
    fn compact_finalize_orphaned_pending_requires_confirm_and_preserves_unknown_effects() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let (mut child, nonce) = spawn_pending_supervisor(&root);

        let before = inspect_native_session_inventory_status_at(&root).unwrap();
        assert_eq!(before.retained_sessions, 1);
        assert_eq!(before.pending_null_outcomes, 1);
        assert_eq!(before.pending_phantom_reserved_bytes, MAX_OUTCOME_BYTES);

        // Without --confirm, compaction must fail closed.
        let denied = compact_native_session_inventory_at(
            &root,
            &NativeSessionInventoryCompactRequest {
                archive_dir: None,
                max_sessions_to_archive: None,
                finalize_orphaned_pending: true,
                min_pending_age_secs: 0,
                confirm: false,
                operator_id: Some("op-test".to_string()),
                reason: Some("reclaim killed workers".to_string()),
            },
        );
        assert!(denied.is_err());

        // Even explicit zero-age finalization cannot replace a live owner's
        // eventual outcome or release its reserved outcome budget.
        let live =
            compact_native_session_inventory_at(&root, &compaction_request(None, true)).unwrap();
        assert_eq!(live.finalized_orphaned_pending, 0);
        assert_eq!(live.after.reserved_bytes, before.reserved_bytes);
        assert!(!outcome_receipt_path(&root, &nonce).exists());
        child.0.kill().unwrap();
        assert!(!child.0.wait().unwrap().success());

        // With explicit --confirm, orphaned pending session receives an honest
        // SupervisionIncomplete + Unproven + Unknown signed outcome, releasing the
        // ~5.35 MiB phantom reservation without claiming clean completion.
        let report = compact_native_session_inventory_at(
            &root,
            &NativeSessionInventoryCompactRequest {
                archive_dir: None,
                max_sessions_to_archive: None,
                finalize_orphaned_pending: true,
                min_pending_age_secs: 0,
                confirm: true,
                operator_id: Some("op-test".to_string()),
                reason: Some("reclaim killed workers".to_string()),
            },
        )
        .unwrap();
        assert_eq!(report.finalized_orphaned_pending, 1);
        assert_eq!(report.after.pending_null_outcomes, 0);
        assert_eq!(report.after.pending_phantom_reserved_bytes, 0);
        assert!(report.after.reserved_bytes < before.reserved_bytes);
        assert_eq!(report.after.incident_or_failed_sessions, 1);
        assert_eq!(report.after.clean_completed_sessions, 0);

        // Forensic read must still report unknown effects & unproven process.
        let inventory = read_inventory_at(&root, None).unwrap();
        assert_eq!(inventory.unknown_effect_sessions, 1);
        assert_eq!(inventory.unproven_process_sessions, 1);
        assert_eq!(
            inventory.records[0].outcome.as_ref().unwrap().kind,
            NativeSessionOutcomeKind::SupervisionIncomplete
        );
    }

    #[test]
    fn compact_cold_archive_preserves_incidents_and_rejects_tamper() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let archive_dir = temp.path().join("cold-archives");

        // 1. Clean completed exit-0 session (eligible for cold archiving).
        let clean_adm = fixture(&root, 51);
        let mut clean_guard =
            NativeSessionInventoryGuard::admit(&root, clean_adm.clone(), 0).unwrap();
        clean_guard.worker_reaped();
        clean_guard.containment_empty();
        clean_guard.finish(
            NativeSessionOutcomeKind::Completed,
            NativeSessionEffectObservation::FinalLedgerObserved {
                effect_count: 1,
                allowed_count: 1,
                denied_count: 0,
                failed_count: 0,
                chain_head_hash: format!("sha256:{}", "11".repeat(32)),
                ledger_sha256: "22".repeat(32),
            },
        );

        // 2. Denied-effect incident session (MUST NEVER be removed by compaction).
        let denied_adm = fixture(&root, 52);
        let mut denied_guard =
            NativeSessionInventoryGuard::admit(&root, denied_adm.clone(), 0).unwrap();
        denied_guard.worker_reaped();
        denied_guard.containment_empty();
        denied_guard.finish(
            NativeSessionOutcomeKind::Completed,
            NativeSessionEffectObservation::FinalLedgerObserved {
                effect_count: 1,
                allowed_count: 0,
                denied_count: 1,
                failed_count: 0,
                chain_head_hash: format!("sha256:{}", "33".repeat(32)),
                ledger_sha256: "44".repeat(32),
            },
        );

        // 3. Pending active session (MUST NEVER be removed by archive compaction).
        let pending_adm = fixture(&root, 53);
        let pending_guard =
            NativeSessionInventoryGuard::admit(&root, pending_adm.clone(), 0).unwrap();
        std::mem::forget(pending_guard);

        let report = compact_native_session_inventory_at(
            &root,
            &NativeSessionInventoryCompactRequest {
                archive_dir: Some(archive_dir),
                max_sessions_to_archive: None,
                finalize_orphaned_pending: false,
                min_pending_age_secs: 300,
                confirm: false,
                operator_id: Some("op-archive".to_string()),
                reason: Some("routine cold archive".to_string()),
            },
        )
        .unwrap();

        assert_eq!(report.archived_clean_sessions, 1);
        assert_eq!(report.after.retained_sessions, 2);
        assert_eq!(report.after.clean_completed_sessions, 0);
        assert_eq!(report.after.incident_or_failed_sessions, 1);
        assert_eq!(report.after.pending_null_outcomes, 1);

        // Hot admission-record slots and identity captures for archived clean sessions
        // must be retired cleanly so `check_admission_record_capacity` reclaims capacity
        // and forensic reconciliation reports zero source errors or untracked captures.
        let retained_record_files = std::fs::read_dir(root.join(ADMISSION_RECORD_DIRECTORY))
            .unwrap()
            .count();
        assert_eq!(retained_record_files, 2);
        let forensics = read_native_session_forensics_at(&root, None).unwrap();
        assert!(
            forensics.source_errors.is_empty(),
            "unexpected forensic source errors after compaction: {:?}",
            forensics.source_errors
        );
        assert!(
            forensics.untracked_identity_captures.is_empty(),
            "unexpected untracked identity captures after compaction: {:?}",
            forensics.untracked_identity_captures
        );
        assert_eq!(forensics.records.len(), 3);
        let archived = forensics
            .records
            .iter()
            .find(|record| record.admission.session_nonce == clean_adm.session_nonce)
            .expect("archived clean session remains discoverable for incident coverage");
        assert_eq!(archived.admission, clean_adm);
        assert!(archived.outcome_recovered_from_receipt);
        assert!(!clean_adm.identity_capture_path.exists());
        assert_eq!(
            load_archived_runtime_evidence_identity(&root, &clean_adm.identity_capture_path)
                .unwrap()
                .unwrap()
                .session_nonce,
            clean_adm.session_nonce,
        );

        let archive_path = report.archive_path.expect("archive path emitted");
        let raw = std::fs::read(&archive_path).unwrap();
        let mut bundle: NativeSessionColdArchiveBundle = serde_json::from_slice(&raw).unwrap();
        let root_key =
            load_runtime_evidence_product_root(&root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH))
                .unwrap();
        verify_native_session_cold_archive(&bundle, &root_key.verifying_key()).unwrap();
        let portable =
            frankenengine_verifier_sdk::native_session::verify_native_session_cold_archive(
                &raw,
                &root_key.verifying_key(),
            )
            .unwrap();
        assert_eq!(portable.session_count, 1);
        assert_eq!(portable.identity_captures_verified, 1);
        assert!(!portable.replay_certified);
        assert!(!portable.original_receipt_signatures_verified);

        // Tampering 1 byte in reason or entry must fail closed.
        bundle.reason.push('!');
        assert!(verify_native_session_cold_archive(&bundle, &root_key.verifying_key()).is_err());
    }

    fn reseal_test_cold_archive(root: &Path, bundle: &mut NativeSessionColdArchiveBundle) {
        use ed25519_dalek::Signer as _;

        let root_key =
            load_runtime_evidence_product_root(&root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH))
                .unwrap();
        for entry in &mut bundle.entries {
            entry.leaf_sha256 = cold_archive_leaf_sha256(
                &entry.admission,
                &entry.outcome,
                entry.identity_capture.as_ref(),
            )
            .unwrap();
        }
        bundle.session_count = bundle.entries.len();
        bundle.merkle_root_sha256 = compute_cold_archive_merkle_root(
            &bundle
                .entries
                .iter()
                .map(|entry| entry.leaf_sha256.clone())
                .collect::<Vec<_>>(),
        );
        bundle.signing_public_key_hex = hex::encode(root_key.verifying_key().as_bytes());
        bundle.signature_hex = hex::encode(
            root_key
                .sign(&cold_archive_signature_preimage(bundle).unwrap())
                .to_bytes(),
        );
    }

    fn clean_test_cold_archive(
        root: &Path,
        marker: u8,
    ) -> (NativeSessionAdmission, NativeSessionColdArchiveBundle) {
        let admission = fixture(root, marker);
        let mut guard = NativeSessionInventoryGuard::admit(root, admission.clone(), 0).unwrap();
        guard.worker_reaped();
        guard.finish(
            NativeSessionOutcomeKind::Completed,
            clean_compaction_ledger_observation(),
        );
        drop(guard);
        let inventory = read_inventory_at(root, None).unwrap();
        let outcome = inventory
            .records
            .iter()
            .find(|record| record.admission.session_nonce == admission.session_nonce)
            .unwrap()
            .outcome
            .clone()
            .unwrap();
        let capture: RuntimeEvidenceIdentityCapture =
            serde_json::from_slice(&std::fs::read(&admission.identity_capture_path).unwrap())
                .unwrap();
        let mut bundle = NativeSessionColdArchiveBundle {
            schema_version: NATIVE_SESSION_COLD_ARCHIVE_SCHEMA.to_owned(),
            archived_at: Utc::now(),
            operator_id: "archive-regression".to_owned(),
            reason: "retain exact public identity and authenticated observations".to_owned(),
            session_count: 1,
            merkle_root_sha256: String::new(),
            signing_public_key_hex: String::new(),
            signature_hex: String::new(),
            entries: vec![NativeSessionColdArchiveEntry {
                session_nonce: admission.session_nonce.clone(),
                leaf_sha256: String::new(),
                admission: admission.clone(),
                outcome,
                identity_capture: Some(capture),
            }],
        };
        reseal_test_cold_archive(root, &mut bundle);
        (admission, bundle)
    }

    fn retain_archive_then_remove_row(
        root: &Path,
        admission: &NativeSessionAdmission,
        bundle: &NativeSessionColdArchiveBundle,
    ) -> PathBuf {
        let key =
            load_runtime_evidence_product_root(&root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH))
                .unwrap()
                .verifying_key();
        let bytes = serde_json::to_vec_pretty(bundle).unwrap();
        let retained = retain_cold_archive(root, &bytes, bundle, &key).unwrap();
        let connection = open_inventory(root, false).unwrap().unwrap();
        let mut tx = connection.transaction().unwrap();
        tx.execute_with_params(
            "DELETE FROM native_sessions WHERE session_nonce = ?1;",
            &[SqliteValue::Text(admission.session_nonce.clone().into())],
        )
        .unwrap();
        tx.commit().unwrap();
        drop(connection);
        protect_sidecars(root).unwrap();
        retained
    }

    #[test]
    fn compact_resumes_archived_retirement_reclaims_capacity_and_shares_session_limit() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let (archived, bundle) = clean_test_cold_archive(&root, 101);
        let retained = retain_archive_then_remove_row(&root, &archived, &bundle);
        let retained_bytes = std::fs::read(&retained).unwrap();
        let (fresh, _) = clean_test_cold_archive(&root, 102);
        let paths = archived_session_sidecar_paths(
            &root,
            &archived.session_nonce,
            &archived.identity_capture_path,
        )
        .unwrap();
        let expected_sidecars = paths.iter().filter(|path| path.exists()).count();
        assert!(expected_sidecars >= 4);
        let capacity = || {
            check_admission_record_capacity(
                &root.join(ADMISSION_RECORD_DIRECTORY),
                1,
                0,
                2,
                MAX_RETAINED_ADMISSION_BYTES,
            )
        };
        assert!(
            capacity().is_err(),
            "the orphaned admission still occupies a slot"
        );
        let mut request = compaction_request(Some(temp.path().join("archive")), false);
        request.max_sessions_to_archive = Some(1);
        let resumed = compact_native_session_inventory_at(&root, &request).unwrap();
        assert_eq!(resumed.retired_archived_sessions, 1);
        assert_eq!(resumed.retired_archived_sidecars, expected_sidecars);
        assert_eq!(resumed.archived_clean_sessions, 0);
        assert!(resumed.archive_path.is_none());
        assert_eq!(resumed.after.retained_sessions, 1);
        assert!(paths.iter().all(|path| !path.exists()));
        assert!(
            capacity().is_ok(),
            "retirement must reclaim the bounded admission slot"
        );
        assert_eq!(
            read_inventory_at(&root, None).unwrap().records[0]
                .admission
                .session_nonce,
            fresh.session_nonce,
        );

        let next = compact_native_session_inventory_at(&root, &request).unwrap();
        assert_eq!(next.retired_archived_sessions, 0);
        assert_eq!(next.retired_archived_sidecars, 0);
        assert_eq!(next.archived_clean_sessions, 1);
        assert_eq!(next.after.retained_sessions, 0);
        let repeat = compact_native_session_inventory_at(&root, &request).unwrap();
        assert_eq!(repeat.retired_archived_sessions, 0);
        assert_eq!(repeat.retired_archived_sidecars, 0);
        assert_eq!(repeat.archived_clean_sessions, 0);
        assert!(repeat.archive_path.is_none());
        assert_eq!(std::fs::read(retained).unwrap(), retained_bytes);
        let forensics = read_native_session_forensics_at(&root, None).unwrap();
        assert!(
            forensics.source_errors.is_empty(),
            "{:?}",
            forensics.source_errors
        );
        assert_eq!(forensics.records.len(), 2);
        assert_eq!(
            load_archived_runtime_evidence_identity(&root, &archived.identity_capture_path)
                .unwrap(),
            bundle.entries[0].identity_capture,
        );
    }

    #[test]
    fn compact_resumes_partial_retirement_only_with_protected_cold_authority() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let (admission, bundle) = clean_test_cold_archive(&root, 103);
        let retained = retain_archive_then_remove_row(&root, &admission, &bundle);
        let body = admission_record_path(&root, &admission.session_nonce);
        let paths = archived_session_sidecar_paths(
            &root,
            &admission.session_nonce,
            &admission.identity_capture_path,
        )
        .unwrap();
        for (index, path) in paths.iter().enumerate() {
            if path != &body && path != &admission.identity_capture_path && path.exists() {
                std::fs::rename(path, temp.path().join(format!("already-retired-{index}")))
                    .unwrap();
            }
        }
        let request = compaction_request(Some(temp.path().join("archive")), false);
        let external_copy = temp.path().join("unavailable-protected-archive.json");
        std::fs::rename(&retained, &external_copy).unwrap();
        let unproven = compact_native_session_inventory_at(&root, &request).unwrap();
        assert_eq!(unproven.retired_archived_sessions, 0);
        assert!(body.exists());
        assert!(admission.identity_capture_path.exists());

        std::fs::rename(external_copy, &retained).unwrap();
        let resumed = compact_native_session_inventory_at(&root, &request).unwrap();
        assert_eq!(resumed.retired_archived_sessions, 1);
        assert_eq!(resumed.retired_archived_sidecars, 2);
        assert_eq!(resumed.archived_clean_sessions, 0);
        assert!(paths.iter().all(|path| !path.exists()));
        assert_eq!(
            load_archived_runtime_evidence_identity(&root, &admission.identity_capture_path)
                .unwrap(),
            bundle.entries[0].identity_capture,
        );
    }

    #[test]
    fn compact_validates_the_complete_retirement_batch_before_unlinking() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let (first, first_bundle) = clean_test_cold_archive(&root, 104);
        retain_archive_then_remove_row(&root, &first, &first_bundle);
        let (second, second_bundle) = clean_test_cold_archive(&root, 105);
        retain_archive_then_remove_row(&root, &second, &second_bundle);
        let mut admissions = [first, second];
        admissions.sort_by(|left, right| left.session_nonce.cmp(&right.session_nonce));
        let first_paths = archived_session_sidecar_paths(
            &root,
            &admissions[0].session_nonce,
            &admissions[0].identity_capture_path,
        )
        .unwrap();
        let first_files: Vec<_> = first_paths
            .iter()
            .filter(|path| path.exists())
            .map(|path| (path.clone(), std::fs::read(path).unwrap()))
            .collect();
        let corrupted_body = admission_record_path(&root, &admissions[1].session_nonce);
        std::fs::write(&corrupted_body, b"{}").unwrap();
        let error = compact_native_session_inventory_at(
            &root,
            &compaction_request(Some(temp.path().join("archive")), false),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("hot admission body disagrees"));
        for (path, expected) in first_files {
            assert_eq!(std::fs::read(path).unwrap(), expected);
        }
        assert_eq!(std::fs::read(corrupted_body).unwrap(), b"{}");
        assert!(admissions[1].identity_capture_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn compact_preserves_archived_residue_while_a_supervisor_lease_is_live() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let (admission, bundle) = clean_test_cold_archive(&root, 106);
        retain_archive_then_remove_row(&root, &admission, &bundle);
        let key =
            load_runtime_evidence_product_root(&root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH))
                .unwrap()
                .verifying_key();
        let ArchiveRetirementLease::Retire(Some(owner)) =
            probe_archive_retirement_lease(&root, &admission, &key).unwrap()
        else {
            panic!("completed fixture must leave an unlocked authenticated lease");
        };
        let request = compaction_request(Some(temp.path().join("archive")), false);
        let blocked = compact_native_session_inventory_at(&root, &request).unwrap();
        assert_eq!(blocked.retired_archived_sessions, 0);
        assert_eq!(blocked.retired_archived_sidecars, 0);
        assert!(admission_record_path(&root, &admission.session_nonce).exists());
        assert!(admission.identity_capture_path.exists());
        drop(owner);
        let resumed = compact_native_session_inventory_at(&root, &request).unwrap();
        assert_eq!(resumed.retired_archived_sessions, 1);
        assert!(!admission.identity_capture_path.exists());
    }

    #[test]
    fn compact_preserves_archived_residue_while_a_fleet_census_holds_it() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let (admission, bundle) = clean_test_cold_archive(&root, 107);
        let history = vec![maintenance_action("interrupted-archive-hold", None)];
        let checkpoint = fleet_application_checkpoint(&history, "prod").unwrap();
        super::begin_drain_at(
            &root,
            &admission.project_root,
            "node-a",
            "prod",
            &checkpoint,
            &history,
        )
        .unwrap();
        let held = finish_drain_at(
            &root,
            &admission.project_root,
            "node-a",
            "prod",
            &checkpoint,
        )
        .unwrap();
        assert!(held.checkpoint.fence_held);
        retain_archive_then_remove_row(&root, &admission, &bundle);
        let compacted = compact_native_session_inventory_at(
            &root,
            &compaction_request(Some(temp.path().join("archive")), false),
        )
        .unwrap();
        assert_eq!(compacted.retired_archived_sessions, 0);
        assert_eq!(compacted.retired_archived_sidecars, 0);
        assert!(admission_record_path(&root, &admission.session_nonce).exists());
        assert!(admission.identity_capture_path.exists());
    }

    #[test]
    fn compact_keeps_identity_and_forensics_when_operator_export_moves() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let (admission, original) = clean_test_cold_archive(&root, 92);
        let expected_capture = original.entries[0].identity_capture.clone().unwrap();
        let compact = compact_native_session_inventory_at(
            &root,
            &compaction_request(Some(temp.path().join("operator-archive")), false),
        )
        .unwrap();
        assert_eq!(compact.archived_clean_sessions, 1);
        assert_eq!(compact.after.retained_sessions, 0);
        assert!(!admission.identity_capture_path.exists());
        assert!(!admission_record_path(&root, &admission.session_nonce).exists());
        std::fs::rename(
            compact.archive_path.unwrap(),
            temp.path().join("moved-operator-export.json"),
        )
        .unwrap();

        assert_eq!(
            load_archived_runtime_evidence_identity(&root, &admission.identity_capture_path)
                .unwrap(),
            Some(expected_capture),
        );
        let forensics =
            read_native_session_forensics_at(&root, Some(&admission.project_root)).unwrap();
        assert!(
            forensics.source_errors.is_empty(),
            "{:?}",
            forensics.source_errors
        );
        assert!(forensics.untracked_identity_captures.is_empty());
        assert_eq!(forensics.records.len(), 1);
        assert_eq!(forensics.records[0].admission, admission);
        assert_eq!(
            forensics.records[0].outcome,
            Some(original.entries[0].outcome.clone())
        );
        assert!(!forensics.replay_certified);
        assert!(!forensics.quiescence_certified);
        assert!(read_inventory_at(&root, None).unwrap().records.is_empty());
    }

    #[test]
    fn cold_archive_tamper_and_missing_copy_never_reconstruct_an_identity() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let (admission, _) = clean_test_cold_archive(&root, 93);
        let compact = compact_native_session_inventory_at(
            &root,
            &compaction_request(Some(temp.path().join("operator-archive")), false),
        )
        .unwrap();
        let bytes = std::fs::read(compact.archive_path.unwrap()).unwrap();
        let retained = retained_cold_archive_path(&root, &bytes);
        let mut tampered = bytes.clone();
        tampered.push(b' ');
        std::fs::write(&retained, tampered).unwrap();
        assert!(
            load_archived_runtime_evidence_identity(&root, &admission.identity_capture_path)
                .is_err()
        );
        let forensics = read_native_session_forensics_at(&root, None).unwrap();
        assert!(
            forensics
                .source_errors
                .iter()
                .any(|error| { error.kind == NativeSessionForensicErrorKind::ColdArchiveInvalid })
        );

        std::fs::write(&retained, &bytes).unwrap();
        std::fs::rename(&retained, temp.path().join("missing-protected-copy.json")).unwrap();
        assert_eq!(
            load_archived_runtime_evidence_identity(&root, &admission.identity_capture_path)
                .unwrap(),
            None,
        );
        // The still-retained project run receipt will now fail identity
        // authentication; absence never fabricates an archived admission.
        assert!(
            read_native_session_forensics_at(&root, None)
                .unwrap()
                .records
                .is_empty()
        );
        assert!(
            load_archived_runtime_evidence_identity(
                &root,
                &temp.path().join("outside-capture.json"),
            )
            .is_err()
        );
    }

    #[test]
    fn cold_archive_merges_exact_hot_observations_but_rejects_conflicts() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let (admission, mut bundle) = clean_test_cold_archive(&root, 94);
        let key =
            load_runtime_evidence_product_root(&root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH))
                .unwrap()
                .verifying_key();
        let bytes = serde_json::to_vec_pretty(&bundle).unwrap();
        let retained = retain_cold_archive(&root, &bytes, &bundle, &key).unwrap();
        assert_eq!(
            retain_cold_archive(&root, &bytes, &bundle, &key).unwrap(),
            retained,
            "retrying an already-published archive must complete the same durability barrier",
        );
        let forensics = read_native_session_forensics_at(&root, None).unwrap();
        assert!(
            forensics.source_errors.is_empty(),
            "{:?}",
            forensics.source_errors
        );
        assert_eq!(forensics.records.len(), 1);
        assert_eq!(forensics.records[0].admission, admission);
        assert!(!forensics.records[0].outcome_recovered_from_receipt);
        assert_eq!(read_inventory_at(&root, None).unwrap().records.len(), 1);

        bundle.entries[0].outcome.observed_at += chrono::Duration::seconds(1);
        reseal_test_cold_archive(&root, &mut bundle);
        let conflicting = serde_json::to_vec_pretty(&bundle).unwrap();
        assert!(retain_cold_archive(&root, &conflicting, &bundle, &key).is_err());

        // Model a separately signed contradictory retained archive, not an
        // unauthenticated byte mutation. It must not replace hot authority.
        std::fs::rename(&retained, temp.path().join("original-cold-copy.json")).unwrap();
        create_new_runtime_evidence_private_file(
            &retained_cold_archive_path(&root, &conflicting),
            &conflicting,
        )
        .unwrap();
        let forensics = read_native_session_forensics_at(&root, None).unwrap();
        assert_eq!(forensics.records.len(), 1);
        assert!(
            forensics
                .source_errors
                .iter()
                .any(|error| { error.kind == NativeSessionForensicErrorKind::ColdArchiveInvalid })
        );
        assert_ne!(
            forensics.records[0].outcome,
            Some(bundle.entries[0].outcome.clone())
        );
    }

    #[test]
    fn cold_archive_reconciles_retired_rows_and_partial_hot_cleanup_without_masking_corruption() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let (admission, bundle) = clean_test_cold_archive(&root, 98);
        let key =
            load_runtime_evidence_product_root(&root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH))
                .unwrap()
                .verifying_key();
        let bytes = serde_json::to_vec_pretty(&bundle).unwrap();
        retain_cold_archive(&root, &bytes, &bundle, &key).unwrap();
        let connection = open_inventory(&root, false).unwrap().unwrap();
        let mut tx = connection.transaction().unwrap();
        tx.execute_with_params(
            "DELETE FROM native_sessions WHERE session_nonce = ?1;",
            &[SqliteValue::Text(admission.session_nonce.clone().into())],
        )
        .unwrap();
        tx.commit().unwrap();
        drop(connection);
        protect_sidecars(&root).unwrap();

        // Exact crash point: cold copy and row deletion are durable, but all
        // per-session hot files still exist. This is explained retirement.
        let forensics = read_native_session_forensics_at(&root, None).unwrap();
        assert!(
            forensics.source_errors.is_empty(),
            "{:?}",
            forensics.source_errors
        );
        assert_eq!(forensics.records.len(), 1);
        assert_eq!(forensics.records[0].admission, admission);
        assert!(forensics.records[0].outcome_recovered_from_receipt);
        assert!(forensics.untracked_identity_captures.is_empty());

        // Directory persistence can expose partial cleanup after a restart.
        // Original signatures are not synthesized from the archive snapshot.
        for (index, path) in [
            admission_receipt_path(&root, &admission.session_nonce),
            outcome_receipt_path(&root, &admission.session_nonce),
            admission.identity_capture_path.clone(),
        ]
        .into_iter()
        .enumerate()
        {
            std::fs::rename(path, temp.path().join(format!("retired-evidence-{index}"))).unwrap();
        }
        let forensics = read_native_session_forensics_at(&root, None).unwrap();
        assert!(
            forensics.source_errors.is_empty(),
            "{:?}",
            forensics.source_errors
        );
        assert_eq!(forensics.records.len(), 1);
        assert_eq!(
            forensics.records[0].outcome,
            Some(bundle.entries[0].outcome.clone())
        );
        assert_eq!(
            load_archived_runtime_evidence_identity(&root, &admission.identity_capture_path)
                .unwrap(),
            bundle.entries[0].identity_capture,
        );

        std::fs::write(
            admission_record_path(&root, &admission.session_nonce),
            b"{}",
        )
        .unwrap();
        let corrupted = read_native_session_forensics_at(&root, None).unwrap();
        assert_eq!(corrupted.records.len(), 1);
        assert!(corrupted.source_errors.iter().any(|error| {
            error.kind == NativeSessionForensicErrorKind::ColdArchiveInvalid
                && error.detail.contains("hot admission body disagrees")
        }));
    }

    #[test]
    fn cold_archive_requires_the_original_identity_and_keeps_v1_verification() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let (_, bundle) = clean_test_cold_archive(&root, 95);
        let key =
            load_runtime_evidence_product_root(&root.join(RUNTIME_EVIDENCE_ROOT_KEY_RELATIVE_PATH))
                .unwrap()
                .verifying_key();
        let other = fixture(&root, 96);
        let other_capture: RuntimeEvidenceIdentityCapture =
            serde_json::from_slice(&std::fs::read(other.identity_capture_path).unwrap()).unwrap();
        let mut replaced = bundle.clone();
        replaced.entries[0].identity_capture = Some(other_capture);
        reseal_test_cold_archive(&root, &mut replaced);
        assert!(verify_native_session_cold_archive(&replaced, &key).is_err());

        let mut legacy = bundle.clone();
        legacy.schema_version = NATIVE_SESSION_COLD_ARCHIVE_V1_SCHEMA.to_owned();
        legacy.entries[0].identity_capture = None;
        reseal_test_cold_archive(&root, &mut legacy);
        verify_native_session_cold_archive(&legacy, &key).unwrap();
        let legacy_bytes = serde_json::to_vec(&legacy).unwrap();
        assert!(retain_cold_archive(&root, &legacy_bytes, &legacy, &key).is_err());
        let mut explicit_null = serde_json::to_value(&legacy).unwrap();
        explicit_null["entries"][0]["identity_capture"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<NativeSessionColdArchiveBundle>(explicit_null).is_err());

        legacy.entries[0].identity_capture = bundle.entries[0].identity_capture.clone();
        reseal_test_cold_archive(&root, &mut legacy);
        assert!(verify_native_session_cold_archive(&legacy, &key).is_err());
        let mut missing = bundle;
        missing.entries[0].identity_capture = None;
        reseal_test_cold_archive(&root, &mut missing);
        assert!(verify_native_session_cold_archive(&missing, &key).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn operator_archive_destination_cannot_poison_protected_cold_retention() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let (admission, _) = clean_test_cold_archive(&root, 99);
        let retained = root.join(COLD_ARCHIVE_DIRECTORY);
        for destination in [retained.clone(), retained.join("nested-export")] {
            let error = compact_native_session_inventory_at(
                &root,
                &compaction_request(Some(destination), false),
            )
            .unwrap_err();
            assert!(error.to_string().contains("overlaps protected"));
            assert!(
                !retained.exists(),
                "refusal must precede directory creation"
            );
        }
        ensure_runtime_evidence_directory(&retained, true).unwrap();
        let alias = temp.path().join("operator-alias");
        symlink(&root, &alias).unwrap();
        let error = compact_native_session_inventory_at(
            &root,
            &compaction_request(Some(alias.join(COLD_ARCHIVE_DIRECTORY)), false),
        )
        .unwrap_err();
        assert!(error.to_string().contains("overlaps protected"));
        assert_eq!(std::fs::read_dir(retained).unwrap().count(), 0);
        assert!(admission.identity_capture_path.exists());
        assert!(admission_record_path(&root, &admission.session_nonce).exists());
        assert_eq!(read_inventory_at(&root, None).unwrap().records.len(), 1);
        assert!(
            read_native_session_forensics_at(&root, None)
                .unwrap()
                .source_errors
                .is_empty()
        );
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_cold_archive_directory_cannot_authorize_hot_retirement() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let (admission, _) = clean_test_cold_archive(&root, 97);
        let outside = temp.path().join("outside-retention");
        ensure_runtime_evidence_directory(&outside, true).unwrap();
        symlink(&outside, root.join(COLD_ARCHIVE_DIRECTORY)).unwrap();
        assert!(
            compact_native_session_inventory_at(
                &root,
                &compaction_request(Some(temp.path().join("operator-archive")), false),
            )
            .is_err()
        );
        assert!(admission.identity_capture_path.exists());
        assert!(admission_record_path(&root, &admission.session_nonce).exists());
        assert_eq!(read_inventory_at(&root, None).unwrap().records.len(), 1);
        assert_eq!(std::fs::read_dir(outside).unwrap().count(), 0);
    }

    #[test]
    fn compact_cold_archive_skips_unproven_outcomes_and_rejects_receipt_mismatch() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");
        let archive_dir = temp.path().join("cold-archives");

        // Admit a session and write a DB outcome WITHOUT a signed outcome receipt.
        let unsigned_adm = fixture(&root, 61);
        let guard = NativeSessionInventoryGuard::admit(&root, unsigned_adm.clone(), 0).unwrap();
        std::mem::forget(guard);
        let fake_clean = NativeSessionOutcome {
            observed_at: Utc::now(),
            kind: NativeSessionOutcomeKind::Completed,
            process: NativeSessionProcessObservation::WorkerReaped,
            containment_empty_observed: true,
            effects: NativeSessionEffectObservation::FinalLedgerObserved {
                effect_count: 1,
                allowed_count: 1,
                denied_count: 0,
                failed_count: 0,
                chain_head_hash: format!("sha256:{}", "55".repeat(32)),
                ledger_sha256: "66".repeat(32),
            },
            panic_evidence: None,
        };
        let conn = open_inventory(&root, false).unwrap().unwrap();
        {
            let mut tx = conn.transaction().unwrap();
            write_observed_outcome(&mut tx, &unsigned_adm, &fake_clean).unwrap();
            tx.commit().unwrap();
        }
        drop(conn);

        // Compaction MUST NOT archive or delete an unproven/unsigned DB outcome.
        let report = compact_native_session_inventory_at(
            &root,
            &NativeSessionInventoryCompactRequest {
                archive_dir: Some(archive_dir.clone()),
                max_sessions_to_archive: None,
                finalize_orphaned_pending: false,
                min_pending_age_secs: 300,
                confirm: false,
                operator_id: Some("op-audit".to_string()),
                reason: Some("verify unproven row retention".to_string()),
            },
        )
        .unwrap();
        assert_eq!(report.archived_clean_sessions, 0);
        assert!(report.archive_path.is_none());
        assert_eq!(report.after.retained_sessions, 1);

        // Now attach a DIFFERENT signed outcome receipt (e.g. SupervisionIncomplete) to
        // prove that DB-vs-receipt disagreement fails closed during cold archive compaction.
        let conflicting = NativeSessionOutcome {
            observed_at: Utc::now(),
            kind: NativeSessionOutcomeKind::SupervisionIncomplete,
            process: NativeSessionProcessObservation::Unproven,
            containment_empty_observed: false,
            effects: NativeSessionEffectObservation::Unknown,
            panic_evidence: None,
        };
        retain_outcome_receipt(&root, &unsigned_adm, &conflicting).unwrap();
        let err = compact_native_session_inventory_at(
            &root,
            &NativeSessionInventoryCompactRequest {
                archive_dir: Some(archive_dir),
                max_sessions_to_archive: None,
                finalize_orphaned_pending: false,
                min_pending_age_secs: 300,
                confirm: false,
                operator_id: Some("op-audit".to_string()),
                reason: Some("must fail on receipt mismatch".to_string()),
            },
        )
        .expect_err("DB outcome disagreeing with signed receipt must fail closed");
        assert!(err.to_string().contains("disagrees with its signed"));
    }

    #[test]
    fn preopened_inventory_reuses_when_fresh_and_observes_concurrent_drain_fence() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime-evidence");

        // Missing DB: preopen must return None without creating files or dirs.
        assert!(open_existing_inventory_for_prewarm_at(&root).is_none());
        assert!(!root.exists());

        // Initialize inventory with one admitted & completed session.
        let admission = fixture(&root, 91);
        let project = admission.project_root.clone();
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission, 0).unwrap();
        guard.worker_started();
        guard.worker_reaped();
        guard.finish(
            NativeSessionOutcomeKind::Completed,
            clean_compaction_ledger_observation(),
        );
        drop(guard);

        // Fresh reuse: preopened connection stays fresh and issues a reusable ticket.
        let preopened =
            open_existing_inventory_for_prewarm_at(&root).expect("existing inventory must preopen");
        assert!(preopened.is_fresh());
        let ticket =
            admission_ticket_with_connection_at_preopened(&root, &project, Some(preopened))
                .expect("fresh preopened inventory must issue open admission ticket");
        assert_eq!(ticket.generation, 0);
        assert!(ticket.connection.is_some());

        // Concurrent drain fence: preopen before another writer commits a held
        // drain fence; ticket acquisition MUST detect the change and refuse.
        let stale_preopened = open_existing_inventory_for_prewarm_at(&root)
            .expect("existing inventory must preopen before concurrent drain");
        let checkpoint = actions(1);
        begin_drain_at(&root, &project, "node-a", "prod", &checkpoint).unwrap();
        assert!(
            !stale_preopened.is_fresh(),
            "concurrent drain commit must invalidate preopened inventory fingerprint"
        );
        let fenced_err =
            admission_ticket_with_connection_at_preopened(&root, &project, Some(stale_preopened))
                .err()
                .expect("admission ticket MUST fail closed on concurrent drain fence");
        assert!(
            fenced_err
                .to_string()
                .contains("fenced by local fleet drain"),
            "unexpected error: {fenced_err:#}"
        );
    }

    #[test]
    fn batched_serialization_and_combined_outcome_bounds_preserve_invariants() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("evidence");
        let admission = fixture(&root, 92);
        let project = admission.project_root.clone();

        // Admit using batched ancestor serialization + single-query drain probe.
        let mut guard = NativeSessionInventoryGuard::admit(&root, admission.clone(), 0).unwrap();
        guard.worker_started();
        guard.worker_reaped();
        let outcome = NativeSessionOutcome {
            observed_at: Utc::now(),
            kind: NativeSessionOutcomeKind::Completed,
            process: NativeSessionProcessObservation::WorkerReaped,
            containment_empty_observed: false,
            effects: clean_compaction_ledger_observation(),
            panic_evidence: None,
        };
        guard.persist_outcome(&outcome).unwrap();

        // Verify all project ancestors were recorded in the serialization table.
        let conn = open_inventory(&root, false).unwrap().unwrap();
        let tx = conn.transaction().unwrap();
        let expected_ancestors: BTreeSet<String> = project
            .ancestors()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let rows = tx
            .query("SELECT project_root FROM native_session_admission_serialization;")
            .unwrap();
        let actual: BTreeSet<String> = rows
            .into_iter()
            .filter_map(|row| match row.values() {
                [SqliteValue::Text(text)] => Some(text.to_string()),
                _ => None,
            })
            .collect();
        assert_eq!(actual, expected_ancestors);

        // Verify combined outcome persistence still rejects conflicting overwrite
        // and missing admissions identically.
        let mut tx_mut = tx;
        let conflicting = NativeSessionOutcome {
            kind: NativeSessionOutcomeKind::ExecutionFailed,
            ..outcome
        };
        let err = write_observed_outcome_and_check_bounds(&mut tx_mut, &admission, &conflicting)
            .expect_err("conflicting outcome must fail immutability check");
        assert!(err.to_string().contains("immutable once observed"), "{err}");

        let mut missing = admission.clone();
        missing.session_nonce = uuid::Uuid::now_v7().to_string();
        let missing_err =
            write_observed_outcome_and_check_bounds(&mut tx_mut, &missing, &conflicting)
                .expect_err("missing admission must fail");
        assert!(
            missing_err
                .to_string()
                .contains("disappeared before outcome persistence"),
            "{missing_err}"
        );
        drop(tx_mut);
        guard.finished = true;
    }
}
