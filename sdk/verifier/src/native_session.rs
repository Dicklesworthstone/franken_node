//! Independent verification of retained native supervisor observations.
//!
//! This format transports the original signed admission and outcome bytes. It
//! does not replay a guest, recover missing history, establish process liveness,
//! or turn a provider return marker into a committed host-effect receipt. The
//! caller supplies the product root independently of the exported evidence.

use std::fmt;

use chrono::{DateTime, Timelike as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::incident_bundle::decode_evidence_json;

pub const NATIVE_SESSION_FORENSICS_SCHEMA: &str = "franken-node/native-session-forensics/v1";
pub const MAX_NATIVE_SESSION_FORENSICS_BYTES: usize = 16 * 1024 * 1024;
const MAX_ADMISSION_BYTES: usize = 4 * 1024 * 1024;
const MAX_WAL_BYTES: usize = 4 * 1024 * 1024;
const MAX_OUTCOME_BYTES: usize = MAX_WAL_BYTES + 1024 * 1024;
const MAX_OUTCOME_PAYLOAD_BYTES: usize = MAX_OUTCOME_BYTES + 1024;
const MAX_PANIC_MESSAGE_BYTES: usize = 4096;
const MAX_WAL_EVENTS: usize = 2048;
const ADMISSION_RECEIPT_SCHEMA: &str = "franken-node/native-session-admission-receipt/v1";
const OUTCOME_RECEIPT_SCHEMA: &str = "franken-node/native-session-outcome-receipt/v1";
const INTERRUPTION_SCHEMA: &str = "franken-node/native-effect-interruption-evidence/v1";
const ADMISSION_HASH_DOMAIN: &[u8] = b"franken-node/native-session-admission/v1\0";
const ADMISSION_SIGNATURE_DOMAIN: &[u8] = b"franken-node/native-session-admission-signature/v1\0";
const OUTCOME_SIGNATURE_DOMAIN: &[u8] = b"franken-node/native-session-outcome-signature/v1\0";

/// Portable envelope, with an explicit `outcome: null` for an observation that
/// has no retained signed outcome. Absence is never inferred to mean success.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSessionForensicBundle {
    pub schema_version: String,
    pub admission_json: String,
    pub admission_receipt: NativeSessionForensicAdmissionReceipt,
    #[serde(deserialize_with = "required_option")]
    pub outcome: Option<NativeSessionForensicOutcome>,
}

impl fmt::Debug for NativeSessionForensicBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeSessionForensicBundle")
            .field("schema_version", &self.schema_version)
            .field("admission_json", &"[redacted]")
            .field("admission_receipt", &self.admission_receipt)
            .field("outcome", &self.outcome)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSessionForensicAdmissionReceipt {
    pub schema_version: String,
    pub session_nonce: String,
    pub product_root_key_id: String,
    pub admission_sha256: String,
    pub signature_hex: String,
}

/// `payload_json` is the original outcome receipt's signing payload, without
/// the signature-domain prefix or length. Its spelling is authenticated intact.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSessionForensicOutcome {
    pub payload_json: String,
    pub signature_hex: String,
}

impl fmt::Debug for NativeSessionForensicOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeSessionForensicOutcome")
            .field("payload_json", &"[redacted]")
            .field("signature_hex", &self.signature_hex)
            .finish()
    }
}

/// A bounded summary of authenticated statements. The private panic text, WAL
/// request commitments and dependency inventory are deliberately not repeated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedNativeSessionForensics {
    pub schema_version: &'static str,
    pub scope: &'static str,
    pub session_nonce: String,
    pub product_root_key_id: String,
    pub admission_sha256: String,
    pub project_root: String,
    pub entrypoint: String,
    pub security_epoch: u64,
    pub admitted_at: String,
    pub observed_at: Option<String>,
    pub outcome_kind: &'static str,
    pub process_observation: Option<&'static str>,
    pub effect_observation: Option<&'static str>,
    pub containment_empty_observed: Option<bool>,
    pub completed_provider_calls: Option<usize>,
    pub indeterminate_provider_calls: Option<usize>,
    pub final_ledger_effect_count: Option<usize>,
    pub failed_effect_count: Option<usize>,
    pub journal_complete: Option<bool>,
    pub replay_certified: bool,
    pub quiescence_certified: bool,
    pub historical_completeness: bool,
}

/// Stable failures do not include private or attacker-controlled evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSessionForensicError {
    InputTooLarge,
    JsonInvalid,
    SchemaUnsupported,
    IdentityInvalid,
    SignerUntrusted,
    AdmissionHashMismatch,
    SignatureMalformed,
    AdmissionSignatureInvalid,
    OutcomeSignatureInvalid,
    ObservationInvalid,
}

impl fmt::Display for NativeSessionForensicError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InputTooLarge => "native-session forensic evidence exceeds its byte bound",
            Self::JsonInvalid => "native-session forensic evidence has invalid or ambiguous JSON",
            Self::SchemaUnsupported => "native-session forensic schema is unsupported",
            Self::IdentityInvalid => "native-session forensic identity or binding is invalid",
            Self::SignerUntrusted => {
                "native-session forensic signer is not the trusted product root"
            }
            Self::AdmissionHashMismatch => "native-session admission commitment does not match",
            Self::SignatureMalformed => "native-session forensic signature encoding is invalid",
            Self::AdmissionSignatureInvalid => "native-session admission signature is invalid",
            Self::OutcomeSignatureInvalid => "native-session outcome signature is invalid",
            Self::ObservationInvalid => "native-session supervisor observation is inconsistent",
        })
    }
}

impl std::error::Error for NativeSessionForensicError {}

fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn nonnull_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    session_nonce: String,
    product_root_key_id: String,
    identity_capture_path: String,
    security_epoch: u64,
    admitted_at: String,
    project_root: String,
    entrypoint: String,
    dependency_ids: Vec<String>,
    #[serde(deserialize_with = "required_option")]
    configured_node_id: Option<String>,
    #[serde(deserialize_with = "required_option")]
    fleet_zone_id: Option<String>,
    #[serde(deserialize_with = "required_option")]
    fleet_policy_sha256: Option<String>,
    #[serde(default)]
    process_spawn_authority_granted: Option<bool>,
    #[serde(default)]
    control_scopes: Option<Vec<ControlScope>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlScope {
    project_root: String,
    admission_generation: u64,
    #[serde(default)]
    fleet_policy_sha256: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutcomePayload {
    schema_version: String,
    session_nonce: String,
    product_root_key_id: String,
    admission_sha256: String,
    outcome: Outcome,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Outcome {
    observed_at: String,
    kind: OutcomeKind,
    process: ProcessObservation,
    containment_empty_observed: bool,
    effects: EffectObservation,
    #[serde(default, deserialize_with = "nonnull_option")]
    panic_evidence: Option<PanicEvidence>,
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OutcomeKind {
    Completed,
    ExecutionFailed,
    ControlStopped,
    Interrupted,
    TelemetryFailed,
    Panicked,
    SupervisionIncomplete,
}

impl OutcomeKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::ExecutionFailed => "execution_failed",
            Self::ControlStopped => "control_stopped",
            Self::Interrupted => "interrupted",
            Self::TelemetryFailed => "telemetry_failed",
            Self::Panicked => "panicked",
            Self::SupervisionIncomplete => "supervision_incomplete",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProcessObservation {
    NotSpawned,
    WorkerReaped,
    Unproven,
}

impl ProcessObservation {
    const fn label(self) -> &'static str {
        match self {
            Self::NotSpawned => "not_spawned",
            Self::WorkerReaped => "worker_reaped",
            Self::Unproven => "unproven",
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum EffectObservation {
    NotStarted,
    NoAdmittedHostEffects,
    FinalLedgerObserved {
        effect_count: usize,
        allowed_count: usize,
        denied_count: usize,
        failed_count: usize,
        chain_head_hash: String,
        ledger_sha256: String,
    },
    Interrupted {
        evidence: InterruptionEvidence,
    },
    Unknown,
}

impl EffectObservation {
    const fn label(&self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::NoAdmittedHostEffects => "no_admitted_host_effects",
            Self::FinalLedgerObserved { .. } => "final_ledger_observed",
            Self::Interrupted { .. } => "interrupted",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PanicEvidence {
    panic_message: String,
    panic_message_bytes: usize,
    panic_message_sha256: String,
    panic_message_truncated: bool,
    cleanup_successful: bool,
    host_effect_wal: Vec<WalEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InterruptionEvidence {
    schema_version: String,
    session_nonce: String,
    terminal_state: String,
    replay_certified: bool,
    journal_complete: bool,
    journal_event_cap: usize,
    completed_effect_count: usize,
    interrupted_effect_count: usize,
    entries: Vec<WalEntry>,
    #[serde(default)]
    protocol_error: Option<String>,
    #[serde(default)]
    control_trigger: Option<ControlTrigger>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlTrigger {
    kind: ControlKind,
    detail: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ControlKind {
    SafeMode,
    ActivationInterrupted,
    ExecutionTrust,
    FleetPolicy,
    FleetPolicyChanged,
    FleetDrain,
    MonitorUnavailable,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WalEntry {
    sequence: u64,
    effect_kind: String,
    request_hash: String,
    state: WalState,
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WalState {
    ProviderReturned,
    InterruptedIndeterminate,
}

fn decode<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    limit: usize,
) -> Result<T, NativeSessionForensicError> {
    if bytes.len() > limit {
        return Err(NativeSessionForensicError::InputTooLarge);
    }
    let value = decode_evidence_json(bytes).map_err(|_| NativeSessionForensicError::JsonInvalid)?;
    serde_json::from_value(value).map_err(|_| NativeSessionForensicError::JsonInvalid)
}

fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest_valid(value: &str) -> bool {
    lowercase_hex(value, 64)
}

fn prefixed_digest_valid(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(digest_valid)
}

fn nonce_valid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
        && value.bytes().any(|byte| byte != b'0' && byte != b'-')
}

fn timestamp_valid(value: &str) -> bool {
    value.len() <= 35
        && DateTime::parse_from_rfc3339(value).is_ok_and(|time| time.nanosecond() < 1_000_000_000)
}

// Parse the producer's absolute path lexically. An offline verifier must not
// consult the original filesystem or interpret a Linux path as a Windows one.
fn absolute_path_parts(value: &str) -> Option<Vec<&str>> {
    if value.is_empty() || value.as_bytes().contains(&0) {
        return None;
    }
    let bytes = value.as_bytes();
    let windows = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\');
    let unc = value.starts_with("\\\\");
    if !value.starts_with('/') && !windows && !unc {
        return None;
    }
    let mut parts = value
        .split(|ch| ch == '/' || ((windows || unc) && ch == '\\'))
        .collect::<Vec<_>>();
    // Root paths and a canonical trailing separator have the same ancestry.
    while parts.len() > 1 && parts.last() == Some(&"") {
        parts.pop();
    }
    if parts.iter().any(|part| matches!(*part, "." | "..")) {
        return None;
    }
    Some(parts)
}

fn validate_admission(admission: &Admission) -> Result<(), NativeSessionForensicError> {
    let project = absolute_path_parts(&admission.project_root)
        .ok_or(NativeSessionForensicError::IdentityInvalid)?;
    let entry = absolute_path_parts(&admission.entrypoint)
        .ok_or(NativeSessionForensicError::IdentityInvalid)?;
    if !nonce_valid(&admission.session_nonce)
        || !admission
            .product_root_key_id
            .strip_prefix("ed25519:")
            .is_some_and(digest_valid)
        || absolute_path_parts(&admission.identity_capture_path).is_none()
        || !entry.starts_with(&project)
        || entry.len() <= project.len()
        || !timestamp_valid(&admission.admitted_at)
        || admission.fleet_zone_id.is_some() != admission.fleet_policy_sha256.is_some()
        || admission
            .fleet_policy_sha256
            .as_deref()
            .is_some_and(|value| !digest_valid(value))
    {
        return Err(NativeSessionForensicError::IdentityInvalid);
    }
    // These are authenticated metadata only, never grants or effect inputs.
    let _ = (&admission.dependency_ids, &admission.configured_node_id);
    if let Some(scopes) = &admission.control_scopes {
        if scopes.len() > 1 {
            return Err(NativeSessionForensicError::IdentityInvalid);
        }
        for scope in scopes {
            let path = absolute_path_parts(&scope.project_root)
                .ok_or(NativeSessionForensicError::IdentityInvalid)?;
            if path == project
                || scope.project_root.len() > 4096
                || path.len() > 128
                || scope
                    .fleet_policy_sha256
                    .as_deref()
                    .is_some_and(|value| !digest_valid(value))
            {
                return Err(NativeSessionForensicError::IdentityInvalid);
            }
            let _ = scope.admission_generation;
        }
    }
    Ok(())
}

fn signing_bytes(domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(domain.len() + 8 + bytes.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    preimage.extend_from_slice(bytes);
    preimage
}

fn signature(value: &str) -> Result<Signature, NativeSessionForensicError> {
    if !lowercase_hex(value, 128) {
        return Err(NativeSessionForensicError::SignatureMalformed);
    }
    let bytes = hex::decode(value).map_err(|_| NativeSessionForensicError::SignatureMalformed)?;
    Signature::from_slice(&bytes).map_err(|_| NativeSessionForensicError::SignatureMalformed)
}

fn validate_wal(entries: &[WalEntry]) -> Result<(usize, usize), NativeSessionForensicError> {
    let invalid = NativeSessionForensicError::ObservationInvalid;
    if entries.len() > MAX_WAL_EVENTS
        || serde_json::to_vec(entries).map_err(|_| invalid)?.len() > MAX_WAL_BYTES
    {
        return Err(invalid);
    }
    let mut completed = 0;
    let mut interrupted = 0;
    for (index, entry) in entries.iter().enumerate() {
        if entry.sequence != index as u64
            || entry.effect_kind.trim().is_empty()
            || !prefixed_digest_valid(&entry.request_hash)
        {
            return Err(invalid);
        }
        match entry.state {
            WalState::ProviderReturned => completed += 1,
            WalState::InterruptedIndeterminate => {
                if index + 1 != entries.len() {
                    return Err(invalid);
                }
                interrupted += 1;
            }
        }
    }
    if completed * 2 + interrupted > MAX_WAL_EVENTS {
        return Err(invalid);
    }
    Ok((completed, interrupted))
}

fn validate_outcome(
    admission: &Admission,
    outcome: &Outcome,
) -> Result<(), NativeSessionForensicError> {
    use EffectObservation as Effects;
    use OutcomeKind as Kind;
    use ProcessObservation as Process;
    let invalid = NativeSessionForensicError::ObservationInvalid;
    if !timestamp_valid(&outcome.observed_at) {
        return Err(invalid);
    }
    if outcome.process == Process::NotSpawned {
        if outcome.kind != Kind::SupervisionIncomplete
            || !matches!(outcome.effects, Effects::NotStarted)
            || outcome.containment_empty_observed
        {
            return Err(invalid);
        }
    } else if matches!(outcome.effects, Effects::NotStarted) {
        return Err(invalid);
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
        return Err(invalid);
    }
    if outcome.kind == Kind::ControlStopped
        && !matches!(outcome.effects, Effects::FinalLedgerObserved { .. })
    {
        return Err(invalid);
    }
    match &outcome.effects {
        Effects::NoAdmittedHostEffects => {
            if outcome.kind != Kind::Panicked
                || outcome.process != Process::WorkerReaped
                || admission.process_spawn_authority_granted != Some(false)
            {
                return Err(invalid);
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
                .and_then(|count| count.checked_add(*failed_count))
                != Some(*effect_count)
                || !prefixed_digest_valid(chain_head_hash)
                || !digest_valid(ledger_sha256)
            {
                return Err(invalid);
            }
        }
        Effects::Interrupted { evidence } => {
            let (completed, interrupted) = validate_wal(&evidence.entries)?;
            if outcome.kind != Kind::Interrupted
                || evidence.schema_version != INTERRUPTION_SCHEMA
                || evidence.session_nonce != admission.session_nonce
                || evidence.replay_certified
                || evidence.journal_event_cap != MAX_WAL_EVENTS
                || evidence.completed_effect_count != completed
                || evidence.interrupted_effect_count != interrupted
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
                return Err(invalid);
            }
            if let Some(trigger) = &evidence.control_trigger {
                let _ = (&trigger.kind, &trigger.detail);
            }
        }
        Effects::NotStarted | Effects::Unknown => {
            if outcome.kind == Kind::Interrupted {
                return Err(invalid);
            }
        }
    }
    if let Some(panic) = &outcome.panic_evidence {
        let (_, interrupted) = validate_wal(&panic.host_effect_wal)?;
        if outcome.kind != Kind::Panicked
            || panic.panic_message.len() > MAX_PANIC_MESSAGE_BYTES
            || panic.panic_message_bytes < panic.panic_message.len()
            || panic.panic_message_truncated
                != (panic.panic_message_bytes > panic.panic_message.len())
            || (panic.panic_message_truncated
                && panic.panic_message_bytes <= MAX_PANIC_MESSAGE_BYTES)
            || !digest_valid(&panic.panic_message_sha256)
            || (!panic.panic_message_truncated
                && panic.panic_message_sha256
                    != hex::encode(Sha256::digest(panic.panic_message.as_bytes())))
            || interrupted != 0
            || (matches!(outcome.effects, Effects::NoAdmittedHostEffects)
                && (!panic.cleanup_successful || !panic.host_effect_wal.is_empty()))
        {
            return Err(invalid);
        }
    }
    Ok(())
}

/// Verify original admission/outcome signatures without consulting a product
/// workspace, executing a guest, or trusting an embedded key.
///
/// # Errors
/// Rejects ambiguous/oversized encodings, identity or signature mismatches and
/// impossible observations. A valid pending export remains a pending admission;
/// it does not prove that no later signed outcome exists elsewhere.
pub fn verify_native_session_forensics(
    input: &[u8],
    trusted_root: &VerifyingKey,
) -> Result<VerifiedNativeSessionForensics, NativeSessionForensicError> {
    let bundle: NativeSessionForensicBundle = decode(input, MAX_NATIVE_SESSION_FORENSICS_BYTES)?;
    if bundle.schema_version != NATIVE_SESSION_FORENSICS_SCHEMA {
        return Err(NativeSessionForensicError::SchemaUnsupported);
    }
    let admission: Admission = decode(bundle.admission_json.as_bytes(), MAX_ADMISSION_BYTES)?;
    validate_admission(&admission)?;
    let receipt = &bundle.admission_receipt;
    if trusted_root.is_weak()
        || receipt.product_root_key_id
            != format!("ed25519:{}", hex::encode(trusted_root.as_bytes()))
    {
        return Err(NativeSessionForensicError::SignerUntrusted);
    }
    if receipt.schema_version != ADMISSION_RECEIPT_SCHEMA
        || receipt.session_nonce != admission.session_nonce
        || receipt.product_root_key_id != admission.product_root_key_id
        || !digest_valid(&receipt.admission_sha256)
    {
        return Err(NativeSessionForensicError::IdentityInvalid);
    }
    let admission_hash = hex::encode(Sha256::digest(signing_bytes(
        ADMISSION_HASH_DOMAIN,
        bundle.admission_json.as_bytes(),
    )));
    if receipt.admission_sha256 != admission_hash {
        return Err(NativeSessionForensicError::AdmissionHashMismatch);
    }
    #[derive(Serialize)]
    struct AdmissionPayload<'a> {
        schema_version: &'a str,
        session_nonce: &'a str,
        product_root_key_id: &'a str,
        admission_sha256: &'a str,
    }
    let payload = serde_json::to_vec(&AdmissionPayload {
        schema_version: &receipt.schema_version,
        session_nonce: &receipt.session_nonce,
        product_root_key_id: &receipt.product_root_key_id,
        admission_sha256: &receipt.admission_sha256,
    })
    .map_err(|_| NativeSessionForensicError::JsonInvalid)?;
    trusted_root
        .verify_strict(
            &signing_bytes(ADMISSION_SIGNATURE_DOMAIN, &payload),
            &signature(&receipt.signature_hex)?,
        )
        .map_err(|_| NativeSessionForensicError::AdmissionSignatureInvalid)?;

    let mut verified = VerifiedNativeSessionForensics {
        schema_version: NATIVE_SESSION_FORENSICS_SCHEMA,
        scope: "authenticated_supervisor_observations",
        session_nonce: admission.session_nonce.clone(),
        product_root_key_id: admission.product_root_key_id.clone(),
        admission_sha256: admission_hash,
        project_root: admission.project_root.clone(),
        entrypoint: admission.entrypoint.clone(),
        security_epoch: admission.security_epoch,
        admitted_at: admission.admitted_at.clone(),
        observed_at: None,
        outcome_kind: "pending",
        process_observation: None,
        effect_observation: None,
        containment_empty_observed: None,
        completed_provider_calls: None,
        indeterminate_provider_calls: None,
        final_ledger_effect_count: None,
        failed_effect_count: None,
        journal_complete: None,
        replay_certified: false,
        quiescence_certified: false,
        historical_completeness: false,
    };
    if let Some(signed_outcome) = bundle.outcome {
        let payload: OutcomePayload = decode(
            signed_outcome.payload_json.as_bytes(),
            MAX_OUTCOME_PAYLOAD_BYTES,
        )?;
        if payload.schema_version != OUTCOME_RECEIPT_SCHEMA
            || payload.session_nonce != admission.session_nonce
            || payload.product_root_key_id != admission.product_root_key_id
            || payload.admission_sha256 != verified.admission_sha256
        {
            return Err(NativeSessionForensicError::IdentityInvalid);
        }
        trusted_root
            .verify_strict(
                &signing_bytes(
                    OUTCOME_SIGNATURE_DOMAIN,
                    signed_outcome.payload_json.as_bytes(),
                ),
                &signature(&signed_outcome.signature_hex)?,
            )
            .map_err(|_| NativeSessionForensicError::OutcomeSignatureInvalid)?;
        validate_outcome(&admission, &payload.outcome)?;
        let outcome = &payload.outcome;
        verified.observed_at = Some(outcome.observed_at.clone());
        verified.outcome_kind = outcome.kind.label();
        verified.process_observation = Some(outcome.process.label());
        verified.effect_observation = Some(outcome.effects.label());
        verified.containment_empty_observed = Some(outcome.containment_empty_observed);
        match &outcome.effects {
            EffectObservation::Interrupted { evidence } => {
                verified.completed_provider_calls = Some(evidence.completed_effect_count);
                verified.indeterminate_provider_calls = Some(evidence.interrupted_effect_count);
                verified.journal_complete = Some(evidence.journal_complete);
            }
            EffectObservation::FinalLedgerObserved {
                effect_count,
                failed_count,
                ..
            } => {
                verified.final_ledger_effect_count = Some(*effect_count);
                verified.failed_effect_count = Some(*failed_count);
            }
            EffectObservation::NoAdmittedHostEffects => {
                verified.completed_provider_calls = Some(0);
                verified.indeterminate_provider_calls = Some(0);
            }
            _ => {}
        }
        if let Some(panic) = &outcome.panic_evidence {
            verified.completed_provider_calls = Some(panic.host_effect_wal.len());
            verified.indeterminate_provider_calls = Some(0);
            verified.journal_complete = Some(true);
        }
    }
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde_json::{Value, json};

    const NONCE: &str = "019a7f53-c180-7001-8001-000000000001";

    // Build producer-shaped signing bytes independently of the verifier's
    // signing helper; cross-repository producer tests exercise real receipts.
    fn sign(key: &SigningKey, domain: &[u8], payload: &str) -> String {
        let bytes = [
            domain,
            &(payload.len() as u64).to_be_bytes(),
            payload.as_bytes(),
        ]
        .concat();
        hex::encode(key.sign(&bytes).to_bytes())
    }

    fn issue_admission(bundle: &mut NativeSessionForensicBundle, key: &SigningKey) {
        let admission: Value = serde_json::from_str(&bundle.admission_json).unwrap();
        let raw = bundle.admission_json.as_bytes();
        let digest = Sha256::digest(
            [
                b"franken-node/native-session-admission/v1\0".as_slice(),
                &(raw.len() as u64).to_be_bytes(),
                raw,
            ]
            .concat(),
        );
        let hash = hex::encode(digest);
        let root = format!("ed25519:{}", hex::encode(key.verifying_key().as_bytes()));
        let nonce = admission["session_nonce"].as_str().unwrap();
        let payload = format!(
            "{{\"schema_version\":\"franken-node/native-session-admission-receipt/v1\",\"session_nonce\":\"{nonce}\",\"product_root_key_id\":\"{root}\",\"admission_sha256\":\"{hash}\"}}"
        );
        bundle.admission_receipt = NativeSessionForensicAdmissionReceipt {
            schema_version: "franken-node/native-session-admission-receipt/v1".into(),
            session_nonce: nonce.into(),
            product_root_key_id: root,
            admission_sha256: hash,
            signature_hex: sign(
                key,
                b"franken-node/native-session-admission-signature/v1\0",
                &payload,
            ),
        };
    }

    fn issue_outcome(bundle: &mut NativeSessionForensicBundle, key: &SigningKey, outcome: Value) {
        let receipt = &bundle.admission_receipt;
        let payload = format!(
            "{{\"schema_version\":\"franken-node/native-session-outcome-receipt/v1\",\"session_nonce\":\"{}\",\"product_root_key_id\":\"{}\",\"admission_sha256\":\"{}\",\"outcome\":{outcome}}}",
            receipt.session_nonce, receipt.product_root_key_id, receipt.admission_sha256,
        );
        bundle.outcome = Some(NativeSessionForensicOutcome {
            signature_hex: sign(
                key,
                b"franken-node/native-session-outcome-signature/v1\0",
                &payload,
            ),
            payload_json: payload,
        });
    }

    fn pending_fixture() -> (SigningKey, NativeSessionForensicBundle) {
        let key = SigningKey::from_bytes(&[42; 32]);
        let mut bundle = NativeSessionForensicBundle {
            schema_version: NATIVE_SESSION_FORENSICS_SCHEMA.into(),
            admission_json: json!({
                "session_nonce": NONCE,
                "product_root_key_id": format!("ed25519:{}", hex::encode(key.verifying_key().as_bytes())),
                "identity_capture_path": "/evidence/captures/original.json",
                "security_epoch": 7,
                "admitted_at": "2026-11-14T12:00:00Z",
                "project_root": "/removed/project",
                "entrypoint": "/removed/project/main.js",
                "dependency_ids": ["private-dependency-name"],
                "configured_node_id": null,
                "fleet_zone_id": null,
                "fleet_policy_sha256": null,
                "process_spawn_authority_granted": false,
                "control_scopes": [],
            }).to_string(),
            admission_receipt: NativeSessionForensicAdmissionReceipt {
                schema_version: String::new(), session_nonce: String::new(),
                product_root_key_id: String::new(), admission_sha256: String::new(),
                signature_hex: String::new(),
            },
            outcome: None,
        };
        issue_admission(&mut bundle, &key);
        (key, bundle)
    }

    fn wal(sequence: usize, state: &str) -> Value {
        json!({"sequence": sequence, "effect_kind": "http", "request_hash": format!("sha256:{}", "a".repeat(64)), "state": state})
    }

    fn interrupted() -> Value {
        json!({
            "observed_at": "2026-11-14T12:00:01Z", "kind": "interrupted", "process": "worker_reaped",
            "containment_empty_observed": false,
            "effects": {"kind": "interrupted", "evidence": {
                "schema_version": "franken-node/native-effect-interruption-evidence/v1",
                "session_nonce": NONCE, "terminal_state": "worker_exit_indeterminate", "replay_certified": false,
                "journal_complete": true, "journal_event_cap": 2048, "completed_effect_count": 1,
                "interrupted_effect_count": 1, "entries": [wal(0, "provider_returned"), wal(1, "interrupted_indeterminate")]
            }}
        })
    }

    fn panic_outcome(message: &str) -> Value {
        json!({
            "observed_at": "2026-11-14T12:00:01Z", "kind": "panicked", "process": "worker_reaped",
            "containment_empty_observed": false, "effects": {"kind": "unknown"},
            "panic_evidence": {"panic_message": message, "panic_message_bytes": message.len(),
                "panic_message_sha256": hex::encode(Sha256::digest(message.as_bytes())),
                "panic_message_truncated": false, "cleanup_successful": true,
                "host_effect_wal": [wal(0, "provider_returned")]}
        })
    }

    fn verify_bundle(
        bundle: &NativeSessionForensicBundle,
        key: &SigningKey,
    ) -> Result<VerifiedNativeSessionForensics, NativeSessionForensicError> {
        verify_native_session_forensics(&serde_json::to_vec(bundle).unwrap(), &key.verifying_key())
    }

    #[test]
    fn pending_admission_remains_pending_without_execution_or_history_claims() {
        let (key, bundle) = pending_fixture();
        let verified = verify_bundle(&bundle, &key).unwrap();
        assert_eq!(verified.session_nonce, NONCE);
        assert_eq!(verified.outcome_kind, "pending");
        assert_eq!(verified.security_epoch, 7);
        assert!(verified.observed_at.is_none());
        assert!(verified.process_observation.is_none());
        assert_eq!(verified.completed_provider_calls, None);
        assert_eq!(verified.indeterminate_provider_calls, None);
        assert_eq!(verified.journal_complete, None);
        assert!(
            !verified.replay_certified
                && !verified.quiescence_certified
                && !verified.historical_completeness
        );
        let summary = serde_json::to_string(&verified).unwrap();
        assert!(!summary.contains("private-dependency-name"));
        assert!(!summary.contains("/evidence/captures"));
    }

    #[test]
    fn interruption_verifies_exact_observation_without_promoting_provider_returns() {
        let (key, mut bundle) = pending_fixture();
        issue_outcome(&mut bundle, &key, interrupted());
        let verified = verify_bundle(&bundle, &key).unwrap();
        assert_eq!(verified.outcome_kind, "interrupted");
        assert_eq!(verified.completed_provider_calls, Some(1));
        assert_eq!(verified.indeterminate_provider_calls, Some(1));
        assert_eq!(verified.journal_complete, Some(true));
        assert_eq!(verified.final_ledger_effect_count, None);
        assert!(!verified.replay_certified && !verified.quiescence_certified);
        let mut incomplete = interrupted();
        incomplete["effects"]["evidence"]["journal_complete"] = json!(false);
        incomplete["effects"]["evidence"]["protocol_error"] = json!("private protocol detail");
        issue_outcome(&mut bundle, &key, incomplete);
        assert_eq!(
            verify_bundle(&bundle, &key).unwrap().journal_complete,
            Some(false)
        );
    }

    #[test]
    fn signed_panic_preserves_commitments_without_disclosing_private_text() {
        let (key, mut bundle) = pending_fixture();
        issue_outcome(&mut bundle, &key, panic_outcome("private panic λ"));
        let verified = verify_bundle(&bundle, &key).unwrap();
        assert_eq!(verified.outcome_kind, "panicked");
        assert_eq!(verified.completed_provider_calls, Some(1));
        assert_eq!(verified.indeterminate_provider_calls, Some(0));
        let summary = serde_json::to_string(&verified).unwrap();
        assert!(!summary.contains("private panic"));
        assert!(!summary.contains(&"a".repeat(64)));
        let debug = format!("{bundle:?}");
        assert!(!debug.contains("private panic") && !debug.contains("private-dependency-name"));
        let mut truncated = panic_outcome(&"x".repeat(4096));
        truncated["panic_evidence"]["panic_message_bytes"] = json!(5000);
        truncated["panic_evidence"]["panic_message_truncated"] = json!(true);
        truncated["panic_evidence"]["panic_message_sha256"] =
            json!(hex::encode(Sha256::digest("x".repeat(5000))));
        issue_outcome(&mut bundle, &key, truncated);
        assert!(verify_bundle(&bundle, &key).is_ok());
    }

    #[test]
    fn finalized_and_unspawned_observations_stay_supervisor_statements() {
        let (key, mut bundle) = pending_fixture();
        for kind in ["completed", "execution_failed", "control_stopped"] {
            let outcome = json!({"observed_at":"2026-11-14T12:00:01Z", "kind":kind, "process":"worker_reaped", "containment_empty_observed":true,
                "effects":{"kind":"final_ledger_observed", "effect_count":3,"allowed_count":1,"denied_count":1,"failed_count":1,
                "chain_head_hash":format!("sha256:{}", "b".repeat(64)), "ledger_sha256":"c".repeat(64)}});
            issue_outcome(&mut bundle, &key, outcome);
            let verified = verify_bundle(&bundle, &key).unwrap();
            assert_eq!(verified.final_ledger_effect_count, Some(3));
            assert_eq!(verified.failed_effect_count, Some(1));
            assert_eq!(verified.completed_provider_calls, None);
            assert_eq!(verified.indeterminate_provider_calls, None);
            assert_eq!(verified.journal_complete, None);
            assert!(!verified.quiescence_certified && !verified.replay_certified);
        }
        issue_outcome(
            &mut bundle,
            &key,
            json!({"observed_at":"2026-11-14T12:00:01Z", "kind":"supervision_incomplete", "process":"not_spawned", "containment_empty_observed":false,"effects":{"kind":"not_started"}}),
        );
        assert_eq!(
            verify_bundle(&bundle, &key).unwrap().process_observation,
            Some("not_spawned")
        );
        let verified = verify_bundle(&bundle, &key).unwrap();
        assert_eq!(verified.completed_provider_calls, None);
        assert_eq!(verified.indeterminate_provider_calls, None);
        assert_eq!(verified.journal_complete, None);
        issue_outcome(
            &mut bundle,
            &key,
            json!({"observed_at":"2026-11-14T12:00:01Z", "kind":"supervision_incomplete", "process":"unproven", "containment_empty_observed":false,"effects":{"kind":"unknown"}}),
        );
        let verified = serde_json::to_value(verify_bundle(&bundle, &key).unwrap()).unwrap();
        assert!(verified["completed_provider_calls"].is_null());
        assert!(verified["indeterminate_provider_calls"].is_null());
        assert!(verified["journal_complete"].is_null());
    }

    #[test]
    fn anchors_signatures_and_exact_raw_bytes_cannot_be_substituted() {
        let (key, mut bundle) = pending_fixture();
        issue_outcome(&mut bundle, &key, interrupted());
        let other = SigningKey::from_bytes(&[43; 32]);
        assert_eq!(
            verify_bundle(&bundle, &other).unwrap_err(),
            NativeSessionForensicError::SignerUntrusted
        );
        let mut changed = bundle.clone();
        changed.admission_json.push(' ');
        assert_eq!(
            verify_bundle(&changed, &key).unwrap_err(),
            NativeSessionForensicError::AdmissionHashMismatch
        );
        let mut changed = bundle.clone();
        changed.outcome.as_mut().unwrap().payload_json.push(' ');
        assert_eq!(
            verify_bundle(&changed, &key).unwrap_err(),
            NativeSessionForensicError::OutcomeSignatureInvalid
        );
        for target in [0, 1] {
            let mut changed = bundle.clone();
            if target == 0 {
                changed.admission_receipt.signature_hex = "00".repeat(64);
            } else {
                changed.outcome.as_mut().unwrap().signature_hex = "00".repeat(64);
            }
            assert!(verify_bundle(&changed, &key).is_err());
            if target == 0 {
                changed.admission_receipt.signature_hex = "invalid".into();
            } else {
                changed.outcome.as_mut().unwrap().signature_hex = "invalid".into();
            }
            assert_eq!(
                verify_bundle(&changed, &key).unwrap_err(),
                NativeSessionForensicError::SignatureMalformed
            );
        }
    }

    #[test]
    fn independently_signed_cross_session_and_admission_substitution_is_rejected() {
        let (key, mut bundle) = pending_fixture();
        issue_outcome(&mut bundle, &key, interrupted());
        let old_outcome = bundle.outcome.clone();
        let mut admission: Value = serde_json::from_str(&bundle.admission_json).unwrap();
        admission["session_nonce"] = json!("019a7f53-c180-7001-8001-000000000002");
        bundle.admission_json = admission.to_string();
        issue_admission(&mut bundle, &key);
        bundle.outcome = old_outcome;
        assert_eq!(
            verify_bundle(&bundle, &key).unwrap_err(),
            NativeSessionForensicError::IdentityInvalid
        );
    }

    #[test]
    fn signed_impossible_interruption_matrix_is_rejected() {
        let (key, mut bundle) = pending_fixture();
        for case in 0..17 {
            let mut outcome = interrupted();
            let evidence = &mut outcome["effects"]["evidence"];
            match case {
                0 => evidence["replay_certified"] = json!(true),
                1 => evidence["session_nonce"] = json!("019a7f53-c180-7001-8001-000000000002"),
                2 => evidence["journal_event_cap"] = json!(4096),
                3 => evidence["completed_effect_count"] = json!(0),
                4 => evidence["interrupted_effect_count"] = json!(0),
                5 => evidence["entries"][0]["sequence"] = json!(9),
                6 => evidence["entries"][0]["state"] = json!("interrupted_indeterminate"),
                7 => evidence["entries"][1]["request_hash"] = json!("sha256:bad"),
                8 => evidence["entries"][0]["effect_kind"] = json!("  "),
                9 => evidence["terminal_state"] = json!("completed"),
                10 => evidence["journal_complete"] = json!(false),
                11 => evidence["terminal_state"] = json!("control_indeterminate"),
                12 => evidence["control_trigger"] = json!({"kind":"fleet_drain","detail":"stop"}),
                13 => outcome["process"] = json!("unproven"),
                14 => outcome["kind"] = json!("completed"),
                15 => outcome["process"] = json!("not_spawned"),
                16 => outcome["effects"] = json!({"kind":"unknown"}),
                _ => unreachable!(),
            }
            issue_outcome(&mut bundle, &key, outcome);
            assert_eq!(
                verify_bundle(&bundle, &key).unwrap_err(),
                NativeSessionForensicError::ObservationInvalid,
                "case {case}"
            );
        }
    }

    #[test]
    fn signed_panic_and_terminal_state_contradictions_are_rejected() {
        let (key, mut bundle) = pending_fixture();
        for case in 0..9 {
            let mut outcome = panic_outcome("private");
            match case {
                0 => outcome["kind"] = json!("completed"),
                1 => outcome["process"] = json!("unproven"),
                2 => outcome["panic_evidence"]["panic_message_bytes"] = json!(0),
                3 => outcome["panic_evidence"]["panic_message_truncated"] = json!(true),
                4 => outcome["panic_evidence"]["panic_message_sha256"] = json!("f".repeat(64)),
                5 => {
                    outcome["panic_evidence"]["host_effect_wal"][0]["state"] =
                        json!("interrupted_indeterminate")
                }
                6 => outcome["effects"] = json!({"kind":"no_admitted_host_effects"}),
                7 => outcome["effects"] = json!({"kind":"not_started"}),
                8 => outcome["observed_at"] = json!("invalid"),
                _ => unreachable!(),
            }
            issue_outcome(&mut bundle, &key, outcome);
            assert_eq!(
                verify_bundle(&bundle, &key).unwrap_err(),
                NativeSessionForensicError::ObservationInvalid,
                "case {case}"
            );
        }
    }

    #[test]
    fn no_effects_panic_requires_explicit_absence_of_spawn_authority() {
        let (key, mut bundle) = pending_fixture();
        let mut outcome = panic_outcome("panic before any effect");
        outcome["effects"] = json!({"kind":"no_admitted_host_effects"});
        outcome["panic_evidence"]["host_effect_wal"] = json!([]);
        issue_outcome(&mut bundle, &key, outcome.clone());
        assert!(verify_bundle(&bundle, &key).is_ok());
        let mut admission: Value = serde_json::from_str(&bundle.admission_json).unwrap();
        admission
            .as_object_mut()
            .unwrap()
            .remove("process_spawn_authority_granted");
        bundle.admission_json = admission.to_string();
        issue_admission(&mut bundle, &key);
        issue_outcome(&mut bundle, &key, outcome);
        assert_eq!(
            verify_bundle(&bundle, &key).unwrap_err(),
            NativeSessionForensicError::ObservationInvalid
        );
    }

    #[test]
    fn duplicates_unknown_fields_null_panic_and_missing_outcome_are_rejected() {
        let (key, mut bundle) = pending_fixture();
        issue_outcome(&mut bundle, &key, interrupted());
        let encoded = serde_json::to_string(&bundle).unwrap();
        let duplicate = encoded.replacen('{', "{\"schema_version\":\"ignored\",", 1);
        assert_eq!(
            verify_native_session_forensics(duplicate.as_bytes(), &key.verifying_key())
                .unwrap_err(),
            NativeSessionForensicError::JsonInvalid
        );
        let mut outer = serde_json::to_value(&bundle).unwrap();
        outer.as_object_mut().unwrap().remove("outcome");
        assert_eq!(
            verify_native_session_forensics(
                &serde_json::to_vec(&outer).unwrap(),
                &key.verifying_key()
            )
            .unwrap_err(),
            NativeSessionForensicError::JsonInvalid
        );
        for case in 0..6 {
            let mut changed = bundle.clone();
            match case {
                0 => {
                    changed.admission_json =
                        changed
                            .admission_json
                            .replacen('{', "{\"session_nonce\":\"ignored\",", 1)
                }
                1 => {
                    changed.outcome.as_mut().unwrap().payload_json =
                        changed.outcome.as_ref().unwrap().payload_json.replacen(
                            "\"replay_certified\":false",
                            "\"replay_certified\":true,\"replay_certified\":false",
                            1,
                        )
                }
                2 => {
                    let mut out = interrupted();
                    out["panic_evidence"] = Value::Null;
                    issue_outcome(&mut changed, &key, out);
                }
                3 => {
                    let mut out = interrupted();
                    out["effects"]["evidence"]["extra"] = json!(true);
                    issue_outcome(&mut changed, &key, out);
                }
                4 => {
                    let mut out = interrupted();
                    out["effects"]["evidence"]["entries"][0]["extra"] = json!(true);
                    issue_outcome(&mut changed, &key, out);
                }
                5 => {
                    let mut outer = serde_json::to_value(&changed).unwrap();
                    outer["extra"] = json!(true);
                    assert_eq!(
                        verify_native_session_forensics(
                            &serde_json::to_vec(&outer).unwrap(),
                            &key.verifying_key()
                        )
                        .unwrap_err(),
                        NativeSessionForensicError::JsonInvalid
                    );
                    continue;
                }
                _ => unreachable!(),
            }
            assert_eq!(
                verify_bundle(&changed, &key).unwrap_err(),
                NativeSessionForensicError::JsonInvalid,
                "case {case}"
            );
        }
    }

    #[test]
    fn wal_event_budget_accepts_boundary_and_rejects_signed_overflow() {
        let (key, mut bundle) = pending_fixture();
        for (completed, interrupted_count, accepted) in [
            (1024, 0, true),
            (1023, 1, true),
            (1024, 1, false),
            (1025, 0, false),
        ] {
            let mut outcome = interrupted();
            let evidence = &mut outcome["effects"]["evidence"];
            let mut entries = (0..completed)
                .map(|i| wal(i, "provider_returned"))
                .collect::<Vec<_>>();
            if interrupted_count > 0 {
                entries.push(wal(completed, "interrupted_indeterminate"));
            }
            evidence["entries"] = json!(entries);
            evidence["completed_effect_count"] = json!(completed);
            evidence["interrupted_effect_count"] = json!(interrupted_count);
            issue_outcome(&mut bundle, &key, outcome);
            assert_eq!(
                verify_bundle(&bundle, &key).is_ok(),
                accepted,
                "{completed} completed, {interrupted_count} interrupted"
            );
        }
    }

    #[test]
    fn input_component_limits_truncation_and_trailing_data_fail_closed() {
        let (key, bundle) = pending_fixture();
        let root = key.verifying_key();
        let encoded = serde_json::to_vec(&bundle).unwrap();
        for bytes in [
            &encoded[..encoded.len() - 1],
            b"".as_slice(),
            b"{} {}".as_slice(),
        ] {
            assert_eq!(
                verify_native_session_forensics(bytes, &root).unwrap_err(),
                NativeSessionForensicError::JsonInvalid
            );
        }
        assert_eq!(
            verify_native_session_forensics(
                &vec![b' '; MAX_NATIVE_SESSION_FORENSICS_BYTES + 1],
                &root
            )
            .unwrap_err(),
            NativeSessionForensicError::InputTooLarge
        );
        let mut changed = bundle.clone();
        changed.admission_json = " ".repeat(MAX_ADMISSION_BYTES + 1);
        assert_eq!(
            verify_bundle(&changed, &key).unwrap_err(),
            NativeSessionForensicError::InputTooLarge
        );
        let mut changed = bundle;
        changed.outcome = Some(NativeSessionForensicOutcome {
            payload_json: " ".repeat(MAX_OUTCOME_PAYLOAD_BYTES + 1),
            signature_hex: "00".repeat(64),
        });
        assert_eq!(
            verify_bundle(&changed, &key).unwrap_err(),
            NativeSessionForensicError::InputTooLarge
        );
    }

    #[test]
    fn signed_bad_admission_identity_and_path_matrix_is_rejected() {
        let (key, bundle) = pending_fixture();
        for case in 0..7 {
            let mut changed = bundle.clone();
            let mut admission: Value = serde_json::from_str(&changed.admission_json).unwrap();
            match case {
                0 => admission["session_nonce"] = json!("00000000-0000-0000-0000-000000000000"),
                1 => admission["entrypoint"] = json!("/removed/project-other/main.js"),
                2 => admission["entrypoint"] = json!("/removed/project/../other.js"),
                3 => admission["identity_capture_path"] = json!("relative.json"),
                4 => admission["fleet_zone_id"] = json!("prod"),
                5 => {
                    admission["control_scopes"] =
                        json!([{"project_root":"/removed/project","admission_generation":1}])
                }
                6 => admission["admitted_at"] = json!("invalid"),
                _ => unreachable!(),
            }
            changed.admission_json = admission.to_string();
            issue_admission(&mut changed, &key);
            assert_eq!(
                verify_bundle(&changed, &key).unwrap_err(),
                NativeSessionForensicError::IdentityInvalid,
                "case {case}"
            );
        }
    }

    #[test]
    fn signed_additional_control_scope_respects_component_bound() {
        let (key, bundle) = pending_fixture();
        for (normal_components, accepted) in [(127, true), (128, false)] {
            let mut changed = bundle.clone();
            let mut admission: Value = serde_json::from_str(&changed.admission_json).unwrap();
            let scope_root = format!("/{}", vec!["scope"; normal_components].join("/"));
            admission["control_scopes"] =
                json!([{"project_root":scope_root,"admission_generation":1}]);
            changed.admission_json = admission.to_string();
            issue_admission(&mut changed, &key);
            assert_eq!(verify_bundle(&changed, &key).is_ok(), accepted);
        }
    }
}
