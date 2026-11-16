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
pub const NATIVE_SESSION_FORENSICS_V2_SCHEMA: &str = "franken-node/native-session-forensics/v2";
pub const MAX_NATIVE_SESSION_FORENSICS_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_NATIVE_SESSION_FORENSICS_V2_BYTES: usize = 32 * 1024 * 1024;
pub const NATIVE_SESSION_EFFECT_JOURNAL_SCHEMA: &str =
    "franken-node/native-effect-journal-record/v1";
pub const MAX_NATIVE_SESSION_EFFECT_JOURNAL_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_NATIVE_SESSION_EFFECT_JOURNAL_RECORD_BYTES: usize = 4096;
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
const JOURNAL_SIGNATURE_DOMAIN: &[u8] = b"franken-node/native-effect-journal-signature/v1\0";
const JOURNAL_RECORD_DOMAIN: &[u8] = b"franken-node/native-effect-journal-record/v1\0";

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
    /// Present only in v2; original newline-delimited signed record bytes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "nonnull_option"
    )]
    pub journal_jsonl: Option<String>,
}

impl fmt::Debug for NativeSessionForensicBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeSessionForensicBundle")
            .field("schema_version", &self.schema_version)
            .field("admission_json", &"[redacted]")
            .field("admission_receipt", &self.admission_receipt)
            .field("outcome", &self.outcome)
            .field(
                "journal_jsonl",
                &self.journal_jsonl.as_ref().map(|_| "[redacted]"),
            )
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

fn serialize_security_epoch<S: serde::Serializer>(
    epoch: &u64,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_str(epoch)
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
    /// Decimal JSON text preserves every authenticated u64 epoch in language
    /// clients. The original signed admission retains its integer encoding.
    #[serde(serialize_with = "serialize_security_epoch")]
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
    pub durable_journal: Option<VerifiedNativeSessionEffectJournal>,
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
    JournalSignatureInvalid,
    JournalInvalid,
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
            Self::JournalSignatureInvalid => "native-session effect journal signature is invalid",
            Self::JournalInvalid => "native-session effect journal prefix is inconsistent",
            Self::ObservationInvalid => "native-session supervisor observation is inconsistent",
        })
    }
}

impl std::error::Error for NativeSessionForensicError {}

/// Authenticated retained prefix of supported host-I/O provider crossings.
/// An admitted call may not have entered its provider; a return marker does
/// not certify its external effect. A prefix never establishes the newest
/// state, process cleanup, all process-spawn effects, or complete guest history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedNativeSessionEffectJournal {
    pub schema_version: &'static str,
    pub scope: &'static str,
    pub session_nonce: String,
    pub product_root_key_id: String,
    pub admission_sha256: String,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EffectJournalRecord {
    payload_json: String,
    signature_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EffectJournalPayload {
    schema_version: String,
    session_nonce: String,
    product_root_key_id: String,
    admission_sha256: String,
    event_index: u64,
    previous_record_sha256: String,
    event: EffectJournalEvent,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum EffectJournalEvent {
    Header {
        scope: String,
        event_cap: usize,
        byte_cap: usize,
    },
    Admitted {
        sequence: u64,
        effect_kind: String,
        request_hash: String,
    },
    ProviderReturned {
        sequence: u64,
    },
}

/// Verify a bounded, root-signed JSONL prefix against an independently selected
/// session and admission commitment. The containing forensic verifier obtains
/// those bindings from the authenticated original admission receipt.
///
/// # Errors
/// Every newline-terminated record must verify. A final non-newline suffix is
/// reported as torn and ignored only after a valid signed header and all prior
/// records verify. An old valid prefix remains a prefix, never complete history.
pub fn verify_native_session_effect_journal(
    bytes: &[u8],
    trusted_root: &VerifyingKey,
    expected_nonce: &str,
    admission_sha256: &str,
) -> Result<VerifiedNativeSessionEffectJournal, NativeSessionForensicError> {
    verify_effect_journal_prefix(bytes, trusted_root, expected_nonce, admission_sha256)
        .map(|prefix| prefix.summary)
}

struct VerifiedEffectJournalPrefix {
    summary: VerifiedNativeSessionEffectJournal,
    entries: Vec<WalEntry>,
}

fn verify_effect_journal_prefix(
    bytes: &[u8],
    trusted_root: &VerifyingKey,
    expected_nonce: &str,
    admission_sha256: &str,
) -> Result<VerifiedEffectJournalPrefix, NativeSessionForensicError> {
    if bytes.len() > MAX_NATIVE_SESSION_EFFECT_JOURNAL_BYTES {
        return Err(NativeSessionForensicError::InputTooLarge);
    }
    if !nonce_valid(expected_nonce) || !digest_valid(admission_sha256) {
        return Err(NativeSessionForensicError::IdentityInvalid);
    }
    if trusted_root.is_weak() {
        return Err(NativeSessionForensicError::SignerUntrusted);
    }
    let root_id = format!("ed25519:{}", hex::encode(trusted_root.as_bytes()));
    let mut verified = VerifiedNativeSessionEffectJournal {
        schema_version: NATIVE_SESSION_EFFECT_JOURNAL_SCHEMA,
        scope: "host_io_provider_calls",
        session_nonce: expected_nonce.to_owned(),
        product_root_key_id: root_id,
        admission_sha256: admission_sha256.to_owned(),
        record_count: 0,
        event_count: 0,
        admitted_provider_calls: 0,
        returned_provider_calls: 0,
        indeterminate_provider_calls: 0,
        head_record_sha256: "0".repeat(64),
        trailing_partial_record: false,
        replay_certified: false,
        quiescence_certified: false,
        historical_completeness: false,
    };
    let mut pending = None;
    let mut entries = Vec::new();
    for fragment in bytes.split_inclusive(|byte| *byte == b'\n') {
        let terminated = fragment.last() == Some(&b'\n');
        let raw = if terminated {
            &fragment[..fragment.len() - 1]
        } else {
            fragment
        };
        if raw.len() > MAX_NATIVE_SESSION_EFFECT_JOURNAL_RECORD_BYTES {
            return Err(NativeSessionForensicError::InputTooLarge);
        }
        if !terminated {
            verified.trailing_partial_record = true;
            break;
        }
        if verified.record_count > MAX_WAL_EVENTS {
            return Err(NativeSessionForensicError::JournalInvalid);
        }
        let record: EffectJournalRecord =
            decode(raw, MAX_NATIVE_SESSION_EFFECT_JOURNAL_RECORD_BYTES)?;
        let payload: EffectJournalPayload = decode(
            record.payload_json.as_bytes(),
            MAX_NATIVE_SESSION_EFFECT_JOURNAL_RECORD_BYTES,
        )?;
        if payload.schema_version != NATIVE_SESSION_EFFECT_JOURNAL_SCHEMA {
            return Err(NativeSessionForensicError::SchemaUnsupported);
        }
        if payload.product_root_key_id != verified.product_root_key_id {
            return Err(NativeSessionForensicError::SignerUntrusted);
        }
        if payload.session_nonce != expected_nonce || payload.admission_sha256 != admission_sha256 {
            return Err(NativeSessionForensicError::IdentityInvalid);
        }
        trusted_root
            .verify_strict(
                &signing_bytes(JOURNAL_SIGNATURE_DOMAIN, record.payload_json.as_bytes()),
                &signature(&record.signature_hex)?,
            )
            .map_err(|_| NativeSessionForensicError::JournalSignatureInvalid)?;
        if payload.event_index != verified.record_count as u64
            || payload.previous_record_sha256 != verified.head_record_sha256
        {
            return Err(NativeSessionForensicError::JournalInvalid);
        }
        match payload.event {
            EffectJournalEvent::Header {
                scope,
                event_cap,
                byte_cap,
            } => {
                if verified.record_count != 0
                    || scope != "host_io_provider_calls"
                    || event_cap != MAX_WAL_EVENTS
                    || byte_cap != MAX_NATIVE_SESSION_EFFECT_JOURNAL_BYTES
                {
                    return Err(NativeSessionForensicError::JournalInvalid);
                }
            }
            EffectJournalEvent::Admitted {
                sequence,
                effect_kind,
                request_hash,
            } => {
                if verified.record_count == 0
                    || pending.is_some()
                    || sequence != verified.admitted_provider_calls as u64
                    || verified.admitted_provider_calls >= MAX_WAL_EVENTS / 2
                    || effect_kind.trim().is_empty()
                    || !prefixed_digest_valid(&request_hash)
                {
                    return Err(NativeSessionForensicError::JournalInvalid);
                }
                pending = Some(sequence);
                verified.admitted_provider_calls += 1;
                entries.push(WalEntry {
                    sequence,
                    effect_kind,
                    request_hash,
                    state: WalState::InterruptedIndeterminate,
                });
            }
            EffectJournalEvent::ProviderReturned { sequence } => {
                if verified.record_count == 0 || pending != Some(sequence) {
                    return Err(NativeSessionForensicError::JournalInvalid);
                }
                pending = None;
                verified.returned_provider_calls += 1;
                if let Some(entry) = entries.last_mut() {
                    entry.state = WalState::ProviderReturned;
                }
            }
        }
        verified.head_record_sha256 =
            hex::encode(Sha256::digest(signing_bytes(JOURNAL_RECORD_DOMAIN, raw)));
        verified.record_count += 1;
    }
    if verified.record_count == 0 {
        return Err(NativeSessionForensicError::JournalInvalid);
    }
    verified.event_count = verified.record_count - 1;
    verified.indeterminate_provider_calls = usize::from(pending.is_some());
    Ok(VerifiedEffectJournalPrefix {
        summary: verified,
        entries,
    })
}

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

fn validate_journal_outcome(
    journal: &[WalEntry],
    outcome: &Outcome,
) -> Result<(), NativeSessionForensicError> {
    let invalid = NativeSessionForensicError::JournalInvalid;
    if !journal.is_empty()
        && matches!(
            outcome.effects,
            EffectObservation::NotStarted | EffectObservation::NoAdmittedHostEffects
        )
    {
        return Err(invalid);
    }
    let (observed, complete) = match (&outcome.effects, &outcome.panic_evidence) {
        (_, Some(panic)) => (panic.host_effect_wal.as_slice(), true),
        (EffectObservation::Interrupted { evidence }, _) => {
            (evidence.entries.as_slice(), evidence.journal_complete)
        }
        _ => return Ok(()),
    };
    if complete && journal.len() > observed.len() {
        return Err(invalid);
    }
    for (durable, observed) in journal.iter().zip(observed) {
        if durable.sequence != observed.sequence
            || durable.effect_kind != observed.effect_kind
            || durable.request_hash != observed.request_hash
            || (complete
                && durable.state == WalState::ProviderReturned
                && observed.state != WalState::ProviderReturned)
        {
            return Err(invalid);
        }
    }
    // A failed response drain can seal an incomplete outcome while a journal
    // append finishes. Later authenticated entries/returns do not repair that
    // outcome or justify rejecting the independently valid retained prefix.
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
    let bundle: NativeSessionForensicBundle = decode(input, MAX_NATIVE_SESSION_FORENSICS_V2_BYTES)?;
    let schema_version = match bundle.schema_version.as_str() {
        NATIVE_SESSION_FORENSICS_SCHEMA => {
            if input.len() > MAX_NATIVE_SESSION_FORENSICS_BYTES {
                return Err(NativeSessionForensicError::InputTooLarge);
            }
            if bundle.journal_jsonl.is_some() {
                return Err(NativeSessionForensicError::SchemaUnsupported);
            }
            NATIVE_SESSION_FORENSICS_SCHEMA
        }
        NATIVE_SESSION_FORENSICS_V2_SCHEMA if bundle.journal_jsonl.is_some() => {
            NATIVE_SESSION_FORENSICS_V2_SCHEMA
        }
        _ => return Err(NativeSessionForensicError::SchemaUnsupported),
    };
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

    let durable_journal = bundle
        .journal_jsonl
        .as_deref()
        .map(|journal| {
            verify_effect_journal_prefix(
                journal.as_bytes(),
                trusted_root,
                &admission.session_nonce,
                &receipt.admission_sha256,
            )
        })
        .transpose()?;

    let mut verified = VerifiedNativeSessionForensics {
        schema_version,
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
        durable_journal: durable_journal
            .as_ref()
            .map(|prefix| prefix.summary.clone()),
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
        if let Some(prefix) = &durable_journal {
            validate_journal_outcome(&prefix.entries, &payload.outcome)?;
        }
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
            journal_jsonl: None,
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
    fn authenticated_epoch_summary_preserves_the_full_u64_range_as_decimal_text() {
        for (epoch, expected) in [
            (0_u64, "0"),
            (7_u64, "7"),
            (9_007_199_254_740_993, "9007199254740993"),
            (u64::MAX, "18446744073709551615"),
        ] {
            let (key, mut bundle) = pending_fixture();
            let mut admission: Value = serde_json::from_str(&bundle.admission_json).unwrap();
            admission["security_epoch"] = json!(epoch);
            bundle.admission_json = admission.to_string();
            issue_admission(&mut bundle, &key);

            let verified = verify_bundle(&bundle, &key).unwrap();
            assert_eq!(verified.security_epoch, epoch);
            let facts = serde_json::to_value(&verified).unwrap();
            assert_eq!(facts["security_epoch"].as_str(), Some(expected));
            assert!(!verified.replay_certified);
            assert!(!verified.quiescence_certified);
        }
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
                &vec![b' '; MAX_NATIVE_SESSION_FORENSICS_V2_BYTES + 1],
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

    fn journal_line(key: &SigningKey, payload: &str) -> String {
        let signature = sign(
            key,
            b"franken-node/native-effect-journal-signature/v1\0",
            payload,
        );
        format!(
            "{{\"payload_json\":{},\"signature_hex\":\"{signature}\"}}",
            serde_json::to_string(payload).unwrap()
        )
    }

    fn journal_hash(line: &str) -> String {
        hex::encode(Sha256::digest(
            [
                b"franken-node/native-effect-journal-record/v1\0".as_slice(),
                &(line.len() as u64).to_be_bytes(),
                line.as_bytes(),
            ]
            .concat(),
        ))
    }

    fn append_journal_event(journal: &mut String, key: &SigningKey, binding: &str, event: Value) {
        let index = journal.lines().count();
        let previous = journal
            .lines()
            .last()
            .map(journal_hash)
            .unwrap_or_else(|| "0".repeat(64));
        let payload = json!({
            "schema_version":"franken-node/native-effect-journal-record/v1",
            "session_nonce":NONCE,
            "product_root_key_id":format!("ed25519:{}", hex::encode(key.verifying_key().as_bytes())),
            "admission_sha256":binding,
            "event_index":index,
            "previous_record_sha256":previous,
            "event":event,
        });
        journal.push_str(&journal_line(key, &payload.to_string()));
        journal.push('\n');
    }

    fn journal_header(key: &SigningKey, binding: &str) -> String {
        let mut journal = String::new();
        append_journal_event(
            &mut journal,
            key,
            binding,
            json!({
                "kind":"header", "scope":"host_io_provider_calls", "event_cap":2048, "byte_cap":4194304,
            }),
        );
        journal
    }

    fn journal_admission(sequence: usize) -> Value {
        json!({"kind":"admitted","sequence":sequence,"effect_kind":"http",
            "request_hash":format!("sha256:{}", "a".repeat(64))})
    }

    #[test]
    fn durable_journal_preserves_admission_without_claiming_provider_execution_or_completion() {
        let (key, mut bundle) = pending_fixture();
        let binding = bundle.admission_receipt.admission_sha256.clone();
        let mut journal = journal_header(&key, &binding);
        append_journal_event(&mut journal, &key, &binding, journal_admission(0));
        bundle.schema_version = NATIVE_SESSION_FORENSICS_V2_SCHEMA.into();
        bundle.journal_jsonl = Some(journal.clone());
        let verified = verify_bundle(&bundle, &key).unwrap();
        assert_eq!(verified.schema_version, NATIVE_SESSION_FORENSICS_V2_SCHEMA);
        assert_eq!(verified.outcome_kind, "pending");
        assert_eq!(verified.process_observation, None);
        assert_eq!(verified.completed_provider_calls, None);
        assert_eq!(verified.indeterminate_provider_calls, None);
        let prefix = verified.durable_journal.unwrap();
        assert_eq!(prefix.record_count, 2);
        assert_eq!(prefix.admitted_provider_calls, 1);
        assert_eq!(prefix.returned_provider_calls, 0);
        assert_eq!(prefix.indeterminate_provider_calls, 1);
        assert!(!prefix.trailing_partial_record);
        assert!(
            !prefix.replay_certified
                && !prefix.quiescence_certified
                && !prefix.historical_completeness
        );
        assert_eq!(
            prefix.head_record_sha256,
            journal_hash(journal.lines().last().unwrap())
        );
        // Cancellation after durable admission but before the provider starts
        // has precisely this prefix: no return or zero-effects claim is added.
        assert_eq!(prefix.scope, "host_io_provider_calls");
        append_journal_event(
            &mut journal,
            &key,
            &binding,
            json!({"kind":"provider_returned","sequence":0}),
        );
        append_journal_event(&mut journal, &key, &binding, journal_admission(1));
        let prefix = verify_native_session_effect_journal(
            journal.as_bytes(),
            &key.verifying_key(),
            NONCE,
            &binding,
        )
        .unwrap();
        assert_eq!(prefix.event_count, 3);
        assert_eq!(prefix.returned_provider_calls, 1);
        assert_eq!(prefix.indeterminate_provider_calls, 1);
    }

    #[test]
    fn durable_journal_torn_tail_needs_verified_header_and_never_hides_complete_corruption() {
        let (key, bundle) = pending_fixture();
        let binding = &bundle.admission_receipt.admission_sha256;
        let header = journal_header(&key, binding);
        let mut complete = header.clone();
        append_journal_event(&mut complete, &key, binding, journal_admission(0));
        let suffix = &complete[header.len()..];
        // Exercise every byte boundary in a genuine signed admission record.
        for length in 1..suffix.len() {
            let mut torn = header.as_bytes().to_vec();
            torn.extend_from_slice(&suffix.as_bytes()[..length]);
            let verified =
                verify_native_session_effect_journal(&torn, &key.verifying_key(), NONCE, binding)
                    .unwrap();
            assert!(verified.trailing_partial_record, "tail length {length}");
            assert_eq!(verified.event_count, 0);
            assert_eq!(verified.admitted_provider_calls, 0);
        }
        for invalid in [
            b"".as_slice(),
            b"{partial".as_slice(),
            header.trim_end().as_bytes(),
        ] {
            assert!(
                verify_native_session_effect_journal(invalid, &key.verifying_key(), NONCE, binding)
                    .is_err()
            );
        }
        for suffix in [b"{partial\n".as_slice(), b"{}\n", b"\n", b"\xff\n"] {
            let mut invalid = header.as_bytes().to_vec();
            invalid.extend_from_slice(suffix);
            assert!(
                verify_native_session_effect_journal(
                    &invalid,
                    &key.verifying_key(),
                    NONCE,
                    binding
                )
                .is_err()
            );
        }
        let mut invalid_header: Value = serde_json::from_str(header.trim_end()).unwrap();
        invalid_header["signature_hex"] = json!("00".repeat(64));
        let invalid = format!("{invalid_header}\n{{partial");
        assert_eq!(
            verify_native_session_effect_journal(
                invalid.as_bytes(),
                &key.verifying_key(),
                NONCE,
                binding
            )
            .unwrap_err(),
            NativeSessionForensicError::JournalSignatureInvalid
        );
    }

    #[test]
    fn durable_journal_authenticates_every_record_binding_and_original_bytes() {
        let (key, bundle) = pending_fixture();
        let binding = &bundle.admission_receipt.admission_sha256;
        let mut journal = journal_header(&key, binding);
        append_journal_event(&mut journal, &key, binding, journal_admission(0));
        let root = key.verifying_key();
        assert!(
            verify_native_session_effect_journal(
                journal.as_bytes(),
                &SigningKey::from_bytes(&[43; 32]).verifying_key(),
                NONCE,
                binding
            )
            .is_err()
        );
        assert!(
            verify_native_session_effect_journal(
                journal.as_bytes(),
                &root,
                "019a7f53-c180-7001-8001-000000000002",
                binding
            )
            .is_err()
        );
        assert!(
            verify_native_session_effect_journal(journal.as_bytes(), &root, NONCE, &"b".repeat(64))
                .is_err()
        );
        let lines = journal.lines().collect::<Vec<_>>();
        let reordered = format!("{}\n{}\n", lines[1], lines[0]);
        let omitted = format!("{}\n", lines[1]);
        let duplicated = format!("{}\n{}\n{}\n", lines[0], lines[1], lines[1]);
        // Altering only the outer envelope spelling changes the chained hash.
        let respelled = format!(" {}\n{}\n", lines[0], lines[1]);
        for invalid in [reordered, omitted, duplicated, respelled] {
            assert_eq!(
                verify_native_session_effect_journal(invalid.as_bytes(), &root, NONCE, binding)
                    .unwrap_err(),
                NativeSessionForensicError::JournalInvalid
            );
        }
        for (field, value) in [
            (
                "session_nonce",
                json!("019a7f53-c180-7001-8001-000000000002"),
            ),
            ("admission_sha256", json!("b".repeat(64))),
            ("event_index", json!(9)),
            ("previous_record_sha256", json!("f".repeat(64))),
        ] {
            let envelope: Value = serde_json::from_str(lines[1]).unwrap();
            let mut payload: Value =
                serde_json::from_str(envelope["payload_json"].as_str().unwrap()).unwrap();
            payload[field] = value;
            let invalid = format!(
                "{}\n{}\n",
                lines[0],
                journal_line(&key, &payload.to_string())
            );
            assert!(
                verify_native_session_effect_journal(invalid.as_bytes(), &root, NONCE, binding)
                    .is_err(),
                "signed {field}"
            );
        }
        let mut envelope: Value = serde_json::from_str(lines[1]).unwrap();
        envelope["payload_json"] =
            json!(format!("{} ", envelope["payload_json"].as_str().unwrap()));
        let tampered = format!("{}\n{envelope}\n", lines[0]);
        assert_eq!(
            verify_native_session_effect_journal(tampered.as_bytes(), &root, NONCE, binding)
                .unwrap_err(),
            NativeSessionForensicError::JournalSignatureInvalid
        );
    }

    #[test]
    fn durable_journal_rejects_signed_impossible_protocol_states() {
        let (key, bundle) = pending_fixture();
        let binding = &bundle.admission_receipt.admission_sha256;
        for case in 0..10 {
            let mut journal = journal_header(&key, binding);
            match case {
                0 => append_journal_event(
                    &mut journal,
                    &key,
                    binding,
                    json!({"kind":"provider_returned","sequence":0}),
                ),
                1 => append_journal_event(&mut journal, &key, binding, journal_admission(1)),
                2 => {
                    append_journal_event(&mut journal, &key, binding, journal_admission(0));
                    append_journal_event(&mut journal, &key, binding, journal_admission(1));
                }
                3 => {
                    append_journal_event(&mut journal, &key, binding, journal_admission(0));
                    append_journal_event(
                        &mut journal,
                        &key,
                        binding,
                        json!({"kind":"provider_returned","sequence":1}),
                    );
                }
                4 | 5 => {
                    let mut event = journal_admission(0);
                    event[if case == 4 {
                        "effect_kind"
                    } else {
                        "request_hash"
                    }] = json!("");
                    append_journal_event(&mut journal, &key, binding, event);
                }
                6 => append_journal_event(
                    &mut journal,
                    &key,
                    binding,
                    json!({"kind":"header","scope":"host_io_provider_calls","event_cap":2048,"byte_cap":4194304}),
                ),
                7..=9 => {
                    journal.clear();
                    let mut header = json!({"kind":"header","scope":"host_io_provider_calls","event_cap":2048,"byte_cap":4194304});
                    header[match case {
                        7 => "scope",
                        8 => "event_cap",
                        _ => "byte_cap",
                    }] = if case == 7 {
                        json!("all_guest_effects")
                    } else {
                        json!(4096)
                    };
                    append_journal_event(&mut journal, &key, binding, header);
                }
                _ => unreachable!(),
            }
            assert_eq!(
                verify_native_session_effect_journal(
                    journal.as_bytes(),
                    &key.verifying_key(),
                    NONCE,
                    binding
                )
                .unwrap_err(),
                NativeSessionForensicError::JournalInvalid,
                "case {case}"
            );
        }
    }

    #[test]
    fn durable_journal_rejects_duplicate_keys_unknown_fields_and_byte_caps() {
        let (key, bundle) = pending_fixture();
        let binding = &bundle.admission_receipt.admission_sha256;
        let header = journal_header(&key, binding);
        let envelope: Value = serde_json::from_str(header.trim_end()).unwrap();
        let payload = envelope["payload_json"].as_str().unwrap();
        for bad_payload in [
            payload.replacen('{', "{\"session_nonce\":\"ignored\",", 1),
            payload.replacen(
                "\"event_cap\":2048",
                "\"event_cap\":2048,\"event_\\u0063ap\":2048",
                1,
            ),
            payload.replacen('{', "{\"unknown\":true,", 1),
            payload.replacen("\"scope\":", "\"unknown\":true,\"scope\":", 1),
        ] {
            let bad = format!("{}\n", journal_line(&key, &bad_payload));
            assert_eq!(
                verify_native_session_effect_journal(
                    bad.as_bytes(),
                    &key.verifying_key(),
                    NONCE,
                    binding
                )
                .unwrap_err(),
                NativeSessionForensicError::JsonInvalid
            );
        }
        let duplicate_outer = header.replacen('{', "{\"signature_hex\":\"ignored\",", 1);
        assert_eq!(
            verify_native_session_effect_journal(
                duplicate_outer.as_bytes(),
                &key.verifying_key(),
                NONCE,
                binding
            )
            .unwrap_err(),
            NativeSessionForensicError::JsonInvalid
        );
        for bad in [
            vec![b' '; MAX_NATIVE_SESSION_EFFECT_JOURNAL_BYTES + 1],
            format!(
                "{header}{}",
                "x".repeat(MAX_NATIVE_SESSION_EFFECT_JOURNAL_RECORD_BYTES + 1)
            )
            .into_bytes(),
        ] {
            assert_eq!(
                verify_native_session_effect_journal(&bad, &key.verifying_key(), NONCE, binding)
                    .unwrap_err(),
                NativeSessionForensicError::InputTooLarge
            );
        }
    }

    #[test]
    fn forensic_versions_require_journal_attachment_and_keep_distinct_byte_limits() {
        let (key, mut bundle) = pending_fixture();
        let mut explicit_null = serde_json::to_value(&bundle).unwrap();
        explicit_null["journal_jsonl"] = Value::Null;
        assert_eq!(
            verify_native_session_forensics(
                &serde_json::to_vec(&explicit_null).unwrap(),
                &key.verifying_key()
            )
            .unwrap_err(),
            NativeSessionForensicError::JsonInvalid
        );
        let journal = journal_header(&key, &bundle.admission_receipt.admission_sha256);
        bundle.journal_jsonl = Some(journal);
        assert_eq!(
            verify_bundle(&bundle, &key).unwrap_err(),
            NativeSessionForensicError::SchemaUnsupported
        );
        bundle.schema_version = NATIVE_SESSION_FORENSICS_V2_SCHEMA.into();
        assert!(verify_bundle(&bundle, &key).is_ok());
        let mut v2 = serde_json::to_vec(&bundle).unwrap();
        v2.resize(MAX_NATIVE_SESSION_FORENSICS_BYTES + 1, b' ');
        assert!(verify_native_session_forensics(&v2, &key.verifying_key()).is_ok());
        bundle.journal_jsonl = None;
        assert_eq!(
            verify_bundle(&bundle, &key).unwrap_err(),
            NativeSessionForensicError::SchemaUnsupported
        );
        bundle.schema_version = NATIVE_SESSION_FORENSICS_SCHEMA.into();
        let mut v1 = serde_json::to_vec(&bundle).unwrap();
        v1.resize(MAX_NATIVE_SESSION_FORENSICS_BYTES + 1, b' ');
        assert_eq!(
            verify_native_session_forensics(&v1, &key.verifying_key()).unwrap_err(),
            NativeSessionForensicError::InputTooLarge
        );
    }

    #[test]
    fn durable_journal_accepts_record_and_event_boundaries_and_rejects_overflow() {
        let (key, bundle) = pending_fixture();
        let binding = &bundle.admission_receipt.admission_sha256;
        let header = journal_header(&key, binding);
        let line = header.trim_end_matches('\n');
        for (extra, accepted) in [(0, true), (1, false)] {
            let bounded = format!(
                "{}{line}\n",
                " ".repeat(MAX_NATIVE_SESSION_EFFECT_JOURNAL_RECORD_BYTES - line.len() + extra)
            );
            assert_eq!(
                verify_native_session_effect_journal(
                    bounded.as_bytes(),
                    &key.verifying_key(),
                    NONCE,
                    binding
                )
                .is_ok(),
                accepted
            );
        }
        let mut journal = header;
        for sequence in 0..1024 {
            append_journal_event(&mut journal, &key, binding, journal_admission(sequence));
            append_journal_event(
                &mut journal,
                &key,
                binding,
                json!({"kind":"provider_returned","sequence":sequence}),
            );
        }
        let verified = verify_native_session_effect_journal(
            journal.as_bytes(),
            &key.verifying_key(),
            NONCE,
            binding,
        )
        .unwrap();
        assert_eq!(verified.record_count, 2049);
        assert_eq!(verified.event_count, 2048);
        assert_eq!(verified.returned_provider_calls, 1024);
        append_journal_event(&mut journal, &key, binding, journal_admission(1024));
        assert_eq!(
            verify_native_session_effect_journal(
                journal.as_bytes(),
                &key.verifying_key(),
                NONCE,
                binding
            )
            .unwrap_err(),
            NativeSessionForensicError::JournalInvalid
        );
    }

    #[test]
    fn forensic_journal_rejects_contradictions_with_complete_signed_outcome_wal() {
        let (key, mut bundle) = pending_fixture();
        let binding = bundle.admission_receipt.admission_sha256.clone();
        let mut journal = journal_header(&key, &binding);
        append_journal_event(&mut journal, &key, &binding, journal_admission(0));
        append_journal_event(
            &mut journal,
            &key,
            &binding,
            json!({"kind":"provider_returned","sequence":0}),
        );
        bundle.schema_version = NATIVE_SESSION_FORENSICS_V2_SCHEMA.into();
        bundle.journal_jsonl = Some(journal.clone());
        issue_outcome(&mut bundle, &key, panic_outcome("private panic"));
        assert!(verify_bundle(&bundle, &key).is_ok());
        for case in 0..4 {
            let mut outcome = panic_outcome("private panic");
            match case {
                0 => {
                    outcome["panic_evidence"]["host_effect_wal"][0]["request_hash"] =
                        json!(format!("sha256:{}", "b".repeat(64)))
                }
                1 => outcome["panic_evidence"]["host_effect_wal"] = json!([]),
                2 => {
                    outcome["effects"] = json!({"kind":"no_admitted_host_effects"});
                    outcome["panic_evidence"]["host_effect_wal"] = json!([]);
                }
                3 => {
                    outcome = json!({"observed_at":"2026-11-14T12:00:01Z","kind":"supervision_incomplete","process":"not_spawned","containment_empty_observed":false,"effects":{"kind":"not_started"}})
                }
                _ => unreachable!(),
            }
            issue_outcome(&mut bundle, &key, outcome);
            assert_eq!(
                verify_bundle(&bundle, &key).unwrap_err(),
                NativeSessionForensicError::JournalInvalid,
                "case {case}"
            );
        }
        append_journal_event(&mut journal, &key, &binding, journal_admission(1));
        bundle.journal_jsonl = Some(journal.clone());
        issue_outcome(&mut bundle, &key, interrupted());
        assert!(verify_bundle(&bundle, &key).is_ok());
        let mut shorter = interrupted();
        shorter["effects"]["evidence"]["entries"]
            .as_array_mut()
            .unwrap()
            .truncate(1);
        shorter["effects"]["evidence"]["interrupted_effect_count"] = json!(0);
        issue_outcome(&mut bundle, &key, shorter);
        assert_eq!(
            verify_bundle(&bundle, &key).unwrap_err(),
            NativeSessionForensicError::JournalInvalid
        );
        append_journal_event(
            &mut journal,
            &key,
            &binding,
            json!({"kind":"provider_returned","sequence":1}),
        );
        bundle.journal_jsonl = Some(journal);
        issue_outcome(&mut bundle, &key, interrupted());
        assert_eq!(
            verify_bundle(&bundle, &key).unwrap_err(),
            NativeSessionForensicError::JournalInvalid
        );
    }

    #[test]
    fn forensic_journal_allows_later_prefix_after_incomplete_or_unknown_outcome() {
        let (key, mut bundle) = pending_fixture();
        let binding = bundle.admission_receipt.admission_sha256.clone();
        let mut journal = journal_header(&key, &binding);
        for sequence in 0..2 {
            append_journal_event(&mut journal, &key, &binding, journal_admission(sequence));
            append_journal_event(
                &mut journal,
                &key,
                &binding,
                json!({"kind":"provider_returned","sequence":sequence}),
            );
        }
        bundle.schema_version = NATIVE_SESSION_FORENSICS_V2_SCHEMA.into();
        bundle.journal_jsonl = Some(journal);
        let mut incomplete = interrupted();
        incomplete["effects"]["evidence"]["journal_complete"] = json!(false);
        incomplete["effects"]["evidence"]["protocol_error"] =
            json!("response drain ended before the journal append finished");
        issue_outcome(&mut bundle, &key, incomplete.clone());
        let verified = verify_bundle(&bundle, &key).unwrap();
        assert_eq!(verified.indeterminate_provider_calls, Some(1));
        assert_eq!(verified.durable_journal.unwrap().returned_provider_calls, 2);
        let mut conflict = incomplete.clone();
        conflict["effects"]["evidence"]["entries"][0]["request_hash"] =
            json!(format!("sha256:{}", "b".repeat(64)));
        issue_outcome(&mut bundle, &key, conflict);
        assert_eq!(
            verify_bundle(&bundle, &key).unwrap_err(),
            NativeSessionForensicError::JournalInvalid
        );
        incomplete["effects"]["evidence"]["entries"] = json!([]);
        incomplete["effects"]["evidence"]["completed_effect_count"] = json!(0);
        incomplete["effects"]["evidence"]["interrupted_effect_count"] = json!(0);
        issue_outcome(&mut bundle, &key, incomplete);
        assert!(verify_bundle(&bundle, &key).is_ok());
        issue_outcome(
            &mut bundle,
            &key,
            json!({"observed_at":"2026-11-14T12:00:01Z","kind":"supervision_incomplete","process":"unproven","containment_empty_observed":false,"effects":{"kind":"unknown"}}),
        );
        let verified = verify_bundle(&bundle, &key).unwrap();
        assert_eq!(verified.completed_provider_calls, None);
        assert_eq!(verified.durable_journal.unwrap().returned_provider_calls, 2);
        assert!(!verified.replay_certified && !verified.quiescence_certified);
    }
}
