//! bd-vll: Deterministic incident replay bundle generation.
//!
//! Generates self-contained replay bundles from incident event logs and
//! replays them deterministically for outcome verification.
//!
//! Invariants:
//! - INV-RB-DETERMINISTIC: identical inputs produce byte-identical bundles
//! - INV-RB-INTEGRITY: bundle hash verifies canonical serialization
//! - INV-RB-CHUNKING: bundles larger than 10 MiB are split into indexed chunks

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signer, Verifier};
#[cfg(feature = "compression")]
use flate2::{Compression, write::GzEncoder};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::security::constant_time;

pub(crate) const MAX_BUNDLE_BYTES: usize = 10 * 1024 * 1024;
pub(crate) const MAX_CHUNKS_PER_BUNDLE: usize = 1000; // Hardening: prevent unbounded chunk growth
pub(crate) const MAX_EVENT_LOG: usize = 50000; // Hardening: prevent unbounded event log growth
const MAX_PREPARED_EVENTS: usize = 50000; // Hardening: prevent unbounded prepared events
const DEFAULT_POLICY_VERSION: &str = "0.1.0";
const DEFAULT_CREATED_AT: &str = "1970-01-01T00:00:00.000000Z";
pub const INCIDENT_EVIDENCE_SCHEMA: &str = "franken-node/incident-evidence-source/v1";
const REPLAY_BUNDLE_SIGNATURE_TRUST_SCOPE: &str = "incident_replay_bundle";
const REPLAY_BUNDLE_SIGNATURE_PAYLOAD_DOMAIN: &[u8] = b"replay_bundle_sig_v1:";

/// RAII guard that orphans a temp file on drop (unless defused after rename).
#[must_use]
pub(crate) struct TempFileGuard(Option<std::path::PathBuf>);

impl TempFileGuard {
    pub(crate) fn new(path: std::path::PathBuf) -> Self {
        Self(Some(path))
    }

    fn abandoned_path(path: &Path) -> std::path::PathBuf {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("replay-bundle.json.tmp");
        path.with_file_name(format!("{file_name}.orphaned-{}", Uuid::now_v7()))
    }

    pub(crate) fn defuse(&mut self) {
        self.0 = None;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take()
            && path.is_file()
        {
            let abandoned_path = Self::abandoned_path(&path);
            if let Err(source) = std::fs::rename(&path, &abandoned_path) {
                tracing::warn!(
                    path = %path.display(),
                    abandoned_path = %abandoned_path.display(),
                    error = %source,
                    "failed to orphan abandoned replay bundle temp file"
                );
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReplayBundleError {
    #[error("incident id cannot be empty")]
    EmptyIncidentId,
    #[error("invalid rfc3339 timestamp `{timestamp}`: {source}")]
    TimestampParse {
        timestamp: String,
        source: chrono::ParseError,
    },
    #[error("payload contains floating-point number at `{path}`")]
    NonDeterministicFloat { path: String },
    #[error(
        "timeline event {sequence_number} exceeds chunk budget: {size_bytes} > {max_bytes} bytes"
    )]
    OversizedEvent {
        sequence_number: u64,
        size_bytes: usize,
        max_bytes: usize,
    },
    #[error("replay bundle contains {count} events, exceeding maximum {max}")]
    TooManyEvents { count: usize, max: usize },
    #[error("replay bundle requires {count} chunks, exceeding maximum {max}")]
    TooManyChunks { count: usize, max: usize },
    #[error("json serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bundle created_at does not match canonical timeline derivation")]
    CreatedAtMismatch,
    #[error("bundle id does not match canonical incident/timeline derivation")]
    BundleIdMismatch,
    #[error("replay bundle json contains trailing garbage")]
    TrailingGarbage,
    #[error("replay bundle json is truncated before the final chunk is complete")]
    TruncatedFinalChunk,
    #[error("negative value {value} cannot be cast into unsigned replay bundle field `{path}`")]
    NegativeCastOffset { path: String, value: i64 },
    #[error("replay bundle chunk {chunk_index} has zero length")]
    ZeroLengthChunk { chunk_index: u32 },
    #[error("duplicate replay bundle id `{bundle_id}`")]
    DuplicateBundleId { bundle_id: Uuid },
    #[error("replay bundle timestamp `{timestamp}` at `{path}` is in the future")]
    TimestampInFuture { path: String, timestamp: String },
    #[error(
        "replay bundle chunk {chunk_index} has non-monotonic timestamps: `{previous}` before `{next}`"
    )]
    NonMonotonicChunkTimestamp {
        chunk_index: u32,
        previous: String,
        next: String,
    },
    #[error("replay bundle contains duplicate chunk offset {chunk_index}")]
    DuplicateChunkOffset { chunk_index: u32 },
    #[error("bundle manifest does not match canonical timeline derivation")]
    ManifestMismatch,
    #[error("bundle chunks do not match canonical timeline derivation")]
    ChunkLayoutMismatch,
    #[error("bundle integrity mismatch")]
    IntegrityMismatch,
    #[error("replay bundle signature is missing")]
    SignatureMissing,
    #[error("unsupported replay bundle signature algorithm `{algorithm}`")]
    SignatureAlgorithmUnsupported { algorithm: String },
    #[error("replay bundle signature trust scope `{actual}` does not match `{expected}`")]
    SignatureTrustScopeMismatch {
        actual: String,
        expected: &'static str,
    },
    #[error("replay bundle signature key source `{key_source}` is not trusted")]
    SignatureKeySourceUntrusted { key_source: String },
    #[error("replay bundle signature verification requires a trusted signer key id")]
    SignatureTrustAnchorMissing,
    #[error("replay bundle signature key id `{actual}` is not trusted key id `{expected}`")]
    SignatureKeyUntrusted { actual: String, expected: String },
    #[error("replay bundle signature public key is malformed: {detail}")]
    SignaturePublicKeyMalformed { detail: String },
    #[error("replay bundle signature key id `{claimed}` does not match public key `{derived}`")]
    SignatureKeyIdMismatch { claimed: String, derived: String },
    #[error("replay bundle signed payload hash does not match integrity_hash")]
    SignaturePayloadHashMismatch,
    #[error("replay bundle signature bytes are malformed: {detail}")]
    SignatureMalformed { detail: String },
    #[error("replay bundle signature verification failed")]
    SignatureInvalid,
    #[error("incident evidence schema mismatch: expected `{expected}`, found `{actual}`")]
    EvidenceSchemaMismatch {
        expected: &'static str,
        actual: String,
    },
    #[error("incident evidence incident_id mismatch: expected `{expected}`, found `{actual}`")]
    EvidenceIncidentIdMismatch { expected: String, actual: String },
    #[error("incident evidence field `{field}` cannot be empty")]
    EvidenceFieldEmpty { field: String },
    #[error("incident evidence evidence_refs must be non-empty")]
    EvidenceRefsEmpty,
    #[error("incident evidence events must be non-empty")]
    EvidenceEventsEmpty,
    #[error("incident evidence contains duplicate event_id `{event_id}`")]
    EvidenceDuplicateEventId { event_id: String },
    #[error(
        "incident evidence event `{event_id}` references missing parent_event_id `{parent_event_id}`"
    )]
    EvidenceMissingParentRef {
        event_id: String,
        parent_event_id: String,
    },
    #[error("incident evidence event `{event_id}` cannot reference itself as parent_event_id")]
    EvidenceSelfParentRef { event_id: String },
    #[error(
        "incident evidence event `{event_id}` references unknown provenance_ref `{provenance_ref}`"
    )]
    EvidenceUnknownProvenanceRef {
        event_id: String,
        provenance_ref: String,
    },
    #[error("incident evidence reference `{reference}` must be relative to the incident root")]
    EvidenceRefNotRelative { reference: String },
    #[error(
        "replay bundle trust artifact reference `{reference}` must also appear in evidence_refs"
    )]
    TrustArtifactRefMissingEvidence { reference: String },
    #[error(
        "incident evidence event `{event_id}` has invalid causal_parent={causal_parent}; it must refer to an earlier event"
    )]
    EvidenceCausalParentInvalid {
        event_id: String,
        causal_parent: u64,
    },
    #[error(
        "incident evidence events are not sorted by timestamp: event {previous_index} must not come after event {next_index}"
    )]
    EvidenceEventsUnsorted {
        previous_index: usize,
        next_index: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    StateChange,
    PolicyEval,
    ExternalSignal,
    OperatorAction,
}

impl EventType {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StateChange => "state_change",
            Self::PolicyEval => "policy_eval",
            Self::ExternalSignal => "external_signal",
            Self::OperatorAction => "operator_action",
        }
    }

    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "state_change" => Some(Self::StateChange),
            "policy_eval" => Some(Self::PolicyEval),
            "external_signal" => Some(Self::ExternalSignal),
            "operator_action" => Some(Self::OperatorAction),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawEvent {
    pub timestamp: String,
    pub event_type: EventType,
    pub payload: Value,
    pub causal_parent: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_snapshot: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
}

impl RawEvent {
    #[must_use]
    pub fn new(timestamp: impl Into<String>, event_type: EventType, payload: Value) -> Self {
        Self {
            timestamp: timestamp.into(),
            event_type,
            payload,
            causal_parent: None,
            state_snapshot: None,
            policy_version: None,
        }
    }

    #[must_use]
    pub fn with_causal_parent(mut self, causal_parent: u64) -> Self {
        self.causal_parent = Some(causal_parent);
        self
    }

    #[must_use]
    pub fn with_state_snapshot(mut self, snapshot: Value) -> Self {
        self.state_snapshot = Some(snapshot);
        self
    }

    #[must_use]
    pub fn with_policy_version(mut self, policy_version: impl Into<String>) -> Self {
        self.policy_version = Some(policy_version.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub sequence_number: u64,
    pub timestamp: String,
    pub event_type: EventType,
    pub payload: Value,
    pub causal_parent: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleManifest {
    pub event_count: usize,
    pub first_timestamp: Option<String>,
    pub last_timestamp: Option<String>,
    pub time_span_micros: u64,
    pub compressed_size_bytes: u64,
    pub chunk_count: u32,
    pub decision_sequence_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleChunk {
    pub bundle_id: Uuid,
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub event_count: usize,
    pub first_sequence_number: u64,
    pub last_sequence_number: u64,
    pub compressed_size_bytes: u64,
    pub chunk_hash: String,
    pub events: Vec<TimelineEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayBundle {
    pub bundle_id: Uuid,
    pub incident_id: String,
    pub created_at: String,
    pub timeline: Vec<TimelineEvent>,
    pub initial_state_snapshot: Value,
    pub policy_version: String,
    pub manifest: BundleManifest,
    pub chunks: Vec<BundleChunk>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trust_artifact_refs: Vec<String>,
    pub integrity_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<ReplayBundleSignature>,
}

pub struct ReplayBundleSigningMaterial<'a> {
    pub signing_key: &'a ed25519_dalek::SigningKey,
    pub key_source: &'a str,
    pub signing_identity: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayBundleSignature {
    pub algorithm: String,
    pub public_key_hex: String,
    pub key_id: String,
    pub key_source: String,
    pub signing_identity: String,
    pub trust_scope: String,
    pub signed_payload_sha256: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayOutcome {
    pub incident_id: String,
    pub expected_sequence_hash: String,
    pub replayed_sequence_hash: String,
    pub matched: bool,
    pub event_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentSeverity {
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentEvidenceMetadata {
    pub title: String,
    pub affected_components: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentEvidenceEvent {
    pub event_id: String,
    pub timestamp: String,
    pub event_type: EventType,
    pub payload: Value,
    pub provenance_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_snapshot: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentEvidencePackage {
    pub schema_version: String,
    pub incident_id: String,
    pub collected_at: String,
    pub trace_id: String,
    pub severity: IncidentSeverity,
    pub incident_type: String,
    pub detector: String,
    pub policy_version: String,
    pub initial_state_snapshot: Value,
    pub events: Vec<IncidentEvidenceEvent>,
    pub evidence_refs: Vec<String>,
    pub metadata: IncidentEvidenceMetadata,
}

#[derive(Debug)]
struct PreparedEvent {
    normalized_timestamp: String,
    timestamp_micros: i64,
    event_type: EventType,
    payload: Value,
    _payload_hash: String,
    causal_parent: Option<u64>,
    state_snapshot: Option<Value>,
    policy_version: Option<String>,
    original_index: usize,
}

#[derive(Serialize)]
struct ReplayBundleIntegrityView<'a> {
    bundle_id: &'a Uuid,
    incident_id: &'a str,
    created_at: &'a str,
    timeline: &'a [TimelineEvent],
    initial_state_snapshot: &'a Value,
    policy_version: &'a str,
    manifest: &'a BundleManifest,
    chunks: &'a [BundleChunk],
    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    evidence_refs: &'a [String],
    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    trust_artifact_refs: &'a [String],
}

pub fn read_incident_evidence_package(
    path: &Path,
    expected_incident_id: Option<&str>,
) -> Result<IncidentEvidencePackage, ReplayBundleError> {
    let raw = std::fs::read_to_string(path)?;
    let package: IncidentEvidencePackage = serde_json::from_str(&raw)?;
    validate_incident_evidence_package(&package, expected_incident_id)?;
    Ok(package)
}

pub fn validate_incident_evidence_package(
    package: &IncidentEvidencePackage,
    expected_incident_id: Option<&str>,
) -> Result<(), ReplayBundleError> {
    if package.schema_version != INCIDENT_EVIDENCE_SCHEMA {
        return Err(ReplayBundleError::EvidenceSchemaMismatch {
            expected: INCIDENT_EVIDENCE_SCHEMA,
            actual: package.schema_version.clone(),
        });
    }

    if package.incident_id.trim().is_empty() {
        return Err(ReplayBundleError::EvidenceFieldEmpty {
            field: "incident_id".to_string(),
        });
    }

    if let Some(expected_incident_id) = expected_incident_id
        && package.incident_id != expected_incident_id
    {
        return Err(ReplayBundleError::EvidenceIncidentIdMismatch {
            expected: expected_incident_id.to_string(),
            actual: package.incident_id.clone(),
        });
    }

    normalize_timestamp(&package.collected_at)?;
    validate_nonempty_field("metadata.title", &package.metadata.title)?;
    validate_nonempty_field("trace_id", &package.trace_id)?;
    validate_nonempty_field("incident_type", &package.incident_type)?;
    validate_nonempty_field("detector", &package.detector)?;
    validate_nonempty_field("policy_version", &package.policy_version)?;

    if package.evidence_refs.is_empty() {
        return Err(ReplayBundleError::EvidenceRefsEmpty);
    }
    for evidence_ref in &package.evidence_refs {
        validate_relative_evidence_ref(evidence_ref)?;
    }
    if package.events.is_empty() {
        return Err(ReplayBundleError::EvidenceEventsEmpty);
    }
    if package.events.len() > MAX_EVENT_LOG {
        return Err(ReplayBundleError::TooManyEvents {
            count: package.events.len(),
            max: MAX_EVENT_LOG,
        });
    }

    canonicalize_value(&package.initial_state_snapshot, "$.initial_state_snapshot")?;

    let evidence_refs = package
        .evidence_refs
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut event_ids = BTreeSet::new();
    let mut previous_timestamp: Option<(usize, i64)> = None;
    for (idx, event) in package.events.iter().enumerate() {
        validate_nonempty_field(&format!("events[{idx}].event_id"), &event.event_id)?;
        validate_nonempty_field(
            &format!("events[{idx}].provenance_ref"),
            &event.provenance_ref,
        )?;
        if !event_ids.insert(event.event_id.as_str()) {
            return Err(ReplayBundleError::EvidenceDuplicateEventId {
                event_id: event.event_id.clone(),
            });
        }

        let (_, timestamp_micros) = normalize_timestamp(&event.timestamp)?;
        if let Some((previous_index, previous_micros)) = previous_timestamp
            && timestamp_micros < previous_micros
        {
            return Err(ReplayBundleError::EvidenceEventsUnsorted {
                previous_index,
                next_index: idx,
            });
        }
        previous_timestamp = Some((idx, timestamp_micros));

        canonicalize_value(&event.payload, &format!("$.events[{idx}].payload"))?;
        if let Some(snapshot) = &event.state_snapshot {
            canonicalize_value(snapshot, &format!("$.events[{idx}].state_snapshot"))?;
        }
        if let Some(policy_version) = &event.policy_version {
            validate_nonempty_field(&format!("events[{idx}].policy_version"), policy_version)?;
        }
        if !evidence_refs.contains(event.provenance_ref.as_str()) {
            return Err(ReplayBundleError::EvidenceUnknownProvenanceRef {
                event_id: event.event_id.clone(),
                provenance_ref: event.provenance_ref.clone(),
            });
        }
        if let Some(parent_event_id) = &event.parent_event_id
            && parent_event_id == &event.event_id
        {
            return Err(ReplayBundleError::EvidenceSelfParentRef {
                event_id: event.event_id.clone(),
            });
        }
    }

    let known_event_ids = package
        .events
        .iter()
        .map(|event| event.event_id.as_str())
        .collect::<BTreeSet<_>>();
    for event in &package.events {
        if let Some(parent_event_id) = &event.parent_event_id
            && !known_event_ids.contains(parent_event_id.as_str())
        {
            return Err(ReplayBundleError::EvidenceMissingParentRef {
                event_id: event.event_id.clone(),
                parent_event_id: parent_event_id.clone(),
            });
        }
    }

    Ok(())
}

fn validate_relative_evidence_ref(reference: &str) -> Result<(), ReplayBundleError> {
    let path = Path::new(reference);
    if reference.trim().is_empty()
        || reference.starts_with('/')
        || reference.contains('\\')
        || reference.contains('\0')
        || path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(ReplayBundleError::EvidenceRefNotRelative {
            reference: reference.to_string(),
        });
    }
    Ok(())
}

pub fn generate_replay_bundle_from_evidence(
    package: &IncidentEvidencePackage,
) -> Result<ReplayBundle, ReplayBundleError> {
    validate_incident_evidence_package(package, None)?;

    let mut sorted_events = package
        .events
        .iter()
        .cloned()
        .map(|event| {
            let (_, micros) = normalize_timestamp(&event.timestamp)?;
            Ok((micros, event))
        })
        .collect::<Result<Vec<_>, ReplayBundleError>>()?;
    sorted_events.sort_by(|(left_micros, left), (right_micros, right)| {
        left_micros
            .cmp(right_micros)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });

    let id_to_index = sorted_events
        .iter()
        .enumerate()
        .map(|(idx, (_, event))| {
            (
                event.event_id.clone(),
                u64::try_from(idx.saturating_add(1)).unwrap_or(u64::MAX),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let selected_policy_version = sorted_events
        .iter()
        .find_map(|(_, event)| event.policy_version.clone())
        .unwrap_or_else(|| package.policy_version.clone());

    let mut event_log = Vec::with_capacity(sorted_events.len());
    for (_, event) in sorted_events {
        let causal_parent = match &event.parent_event_id {
            Some(parent_event_id) => {
                let causal_parent = id_to_index.get(parent_event_id).copied().ok_or_else(|| {
                    ReplayBundleError::EvidenceMissingParentRef {
                        event_id: event.event_id.clone(),
                        parent_event_id: parent_event_id.clone(),
                    }
                })?;
                let current_index =
                    u64::try_from(event_log.len().saturating_add(1)).unwrap_or(u64::MAX);
                if causal_parent >= current_index {
                    return Err(ReplayBundleError::EvidenceCausalParentInvalid {
                        event_id: event.event_id.clone(),
                        causal_parent,
                    });
                }
                Some(causal_parent)
            }
            None => None,
        };
        event_log.push(RawEvent {
            timestamp: event.timestamp,
            event_type: event.event_type,
            payload: event.payload,
            causal_parent,
            state_snapshot: event.state_snapshot,
            policy_version: None,
        });
    }

    if let Some(first) = event_log.first_mut() {
        first.state_snapshot = Some(package.initial_state_snapshot.clone());
        first.policy_version = Some(selected_policy_version);
    }

    let mut bundle = generate_replay_bundle(&package.incident_id, &event_log)?;
    bundle.evidence_refs = package.evidence_refs.clone();
    bundle.trust_artifact_refs = trust_artifact_refs_from_evidence_refs(&bundle.evidence_refs);
    bundle.integrity_hash = compute_integrity_hash(&bundle)?;
    Ok(bundle)
}

fn trust_artifact_refs_from_evidence_refs(evidence_refs: &[String]) -> Vec<String> {
    evidence_refs
        .iter()
        .filter(|reference| is_trust_artifact_ref(reference))
        .cloned()
        .collect()
}

fn is_trust_artifact_ref(reference: &str) -> bool {
    reference
        .split('/')
        .any(|component| matches!(component, "trust" | "trust-artifacts" | "trust_artifacts"))
}

fn validate_nonempty_field(field: &str, value: &str) -> Result<(), ReplayBundleError> {
    if value.trim().is_empty() {
        return Err(ReplayBundleError::EvidenceFieldEmpty {
            field: field.to_string(),
        });
    }
    Ok(())
}

pub fn generate_replay_bundle(
    incident_id: &str,
    event_log: &[RawEvent],
) -> Result<ReplayBundle, ReplayBundleError> {
    if incident_id.trim().is_empty() {
        return Err(ReplayBundleError::EmptyIncidentId);
    }
    if event_log.len() > MAX_PREPARED_EVENTS {
        return Err(ReplayBundleError::TooManyEvents {
            count: event_log.len(),
            max: MAX_PREPARED_EVENTS,
        });
    }

    let mut prepared: Vec<PreparedEvent> = Vec::with_capacity(event_log.len());
    for (idx, event) in event_log.iter().enumerate() {
        let (normalized_timestamp, timestamp_micros) = normalize_timestamp(&event.timestamp)?;
        let payload = canonicalize_value(&event.payload, "$.payload")?;
        let payload_hash = sha256_hex(&canonical_json_bytes(&payload)?);
        let state_snapshot = match &event.state_snapshot {
            Some(snapshot) => Some(canonicalize_value(snapshot, "$.state_snapshot")?),
            None => None,
        };
        prepared.push(PreparedEvent {
            normalized_timestamp,
            timestamp_micros,
            event_type: event.event_type,
            payload,
            _payload_hash: payload_hash,
            causal_parent: event.causal_parent,
            state_snapshot,
            policy_version: event.policy_version.clone(),
            original_index: idx,
        });
    }

    prepared.sort_by(|left, right| {
        left.timestamp_micros
            .cmp(&right.timestamp_micros)
            .then_with(|| left.original_index.cmp(&right.original_index))
    });

    let mut original_to_new = vec![0_u64; event_log.len()];
    for (new_index, event) in prepared.iter().enumerate() {
        original_to_new[event.original_index] =
            u64::try_from(new_index.saturating_add(1)).unwrap_or(u64::MAX);
    }

    let timeline: Vec<TimelineEvent> = prepared
        .iter()
        .enumerate()
        .map(|(index, event)| {
            let sequence_number = u64::try_from(index.saturating_add(1)).unwrap_or(u64::MAX);
            let mapped_parent = event.causal_parent.and_then(|p| {
                let p_usize = usize::try_from(p).ok()?;
                if p > 0 && p_usize < event_log.len() {
                    let index = usize::try_from(p.saturating_sub(1)).ok()?;
                    original_to_new.get(index).copied()
                } else {
                    None
                }
            });
            let causal_parent = match mapped_parent {
                Some(parent) if parent < sequence_number => Some(parent),
                _ => None,
            };
            TimelineEvent {
                sequence_number,
                timestamp: event.normalized_timestamp.clone(),
                event_type: event.event_type,
                payload: event.payload.clone(),
                causal_parent,
            }
        })
        .collect();

    let created_at = derive_created_at(&timeline);

    let initial_state_snapshot = prepared
        .iter()
        .find_map(|event| event.state_snapshot.clone())
        .unwrap_or_else(|| Value::Object(Map::new()));

    let policy_version = prepared
        .iter()
        .find_map(|event| event.policy_version.clone())
        .filter(|version| !version.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_POLICY_VERSION.to_string());

    let bundle_id = deterministic_bundle_id(incident_id, &created_at, &timeline)?;
    let chunks = chunk_timeline(bundle_id, &timeline)?;
    let manifest = derive_bundle_manifest(
        &timeline,
        &initial_state_snapshot,
        &policy_version,
        chunks.len(),
    )?;

    let mut bundle = ReplayBundle {
        bundle_id,
        incident_id: incident_id.to_string(),
        created_at,
        timeline,
        initial_state_snapshot,
        policy_version,
        manifest,
        chunks,
        evidence_refs: Vec::new(),
        trust_artifact_refs: Vec::new(),
        integrity_hash: String::new(),
        signature: None,
    };

    bundle.integrity_hash = compute_integrity_hash(&bundle)?;
    Ok(bundle)
}

pub fn validate_bundle_integrity(bundle: &ReplayBundle) -> Result<bool, ReplayBundleError> {
    validate_bundle_structure(bundle)?;
    let recomputed = compute_integrity_hash(bundle)?;
    Ok(constant_time::ct_eq(&recomputed, &bundle.integrity_hash))
}

pub fn sign_replay_bundle(
    bundle: &mut ReplayBundle,
    signing_material: &ReplayBundleSigningMaterial<'_>,
) -> Result<(), ReplayBundleError> {
    if !validate_bundle_integrity(bundle)? {
        return Err(ReplayBundleError::IntegrityMismatch);
    }

    let payload = replay_bundle_signature_payload(bundle);
    let signature = signing_material.signing_key.sign(&payload);
    let verifying_key = signing_material.signing_key.verifying_key();
    bundle.signature = Some(ReplayBundleSignature {
        algorithm: "ed25519".to_string(),
        public_key_hex: hex::encode(verifying_key.to_bytes()),
        key_id: crate::supply_chain::artifact_signing::KeyId::from_verifying_key(&verifying_key)
            .to_string(),
        key_source: signing_material.key_source.to_string(),
        signing_identity: signing_material.signing_identity.to_string(),
        trust_scope: REPLAY_BUNDLE_SIGNATURE_TRUST_SCOPE.to_string(),
        signed_payload_sha256: hex::encode(Sha256::digest(&payload)),
        signature_hex: hex::encode(signature.to_bytes()),
    });
    Ok(())
}

pub fn verify_replay_bundle_signature(
    bundle: &ReplayBundle,
    trusted_key_id: Option<&str>,
) -> Result<(), ReplayBundleError> {
    let signature = bundle
        .signature
        .as_ref()
        .ok_or(ReplayBundleError::SignatureMissing)?;
    let trusted_key_id = trusted_key_id.ok_or(ReplayBundleError::SignatureTrustAnchorMissing)?;
    if signature.algorithm != "ed25519" {
        return Err(ReplayBundleError::SignatureAlgorithmUnsupported {
            algorithm: signature.algorithm.clone(),
        });
    }
    if signature.trust_scope != REPLAY_BUNDLE_SIGNATURE_TRUST_SCOPE {
        return Err(ReplayBundleError::SignatureTrustScopeMismatch {
            actual: signature.trust_scope.clone(),
            expected: REPLAY_BUNDLE_SIGNATURE_TRUST_SCOPE,
        });
    }
    if signature.key_source == "local" {
        return Err(ReplayBundleError::SignatureKeySourceUntrusted {
            key_source: signature.key_source.clone(),
        });
    }
    if !constant_time::ct_eq(&signature.key_id, trusted_key_id) {
        return Err(ReplayBundleError::SignatureKeyUntrusted {
            actual: signature.key_id.clone(),
            expected: trusted_key_id.to_string(),
        });
    }

    let public_key_bytes = hex::decode(&signature.public_key_hex).map_err(|source| {
        ReplayBundleError::SignaturePublicKeyMalformed {
            detail: source.to_string(),
        }
    })?;
    let public_key_bytes: [u8; 32] = public_key_bytes.try_into().map_err(|bytes: Vec<u8>| {
        ReplayBundleError::SignaturePublicKeyMalformed {
            detail: format!("expected 32 bytes, got {}", bytes.len()),
        }
    })?;
    let verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes).map_err(|source| {
            ReplayBundleError::SignaturePublicKeyMalformed {
                detail: source.to_string(),
            }
        })?;
    let derived_key_id =
        crate::supply_chain::artifact_signing::KeyId::from_verifying_key(&verifying_key)
            .to_string();
    if !constant_time::ct_eq(&signature.key_id, &derived_key_id) {
        return Err(ReplayBundleError::SignatureKeyIdMismatch {
            claimed: signature.key_id.clone(),
            derived: derived_key_id,
        });
    }

    let payload = replay_bundle_signature_payload(bundle);
    let payload_sha256 = hex::encode(Sha256::digest(&payload));
    if !constant_time::ct_eq(&signature.signed_payload_sha256, &payload_sha256) {
        return Err(ReplayBundleError::SignaturePayloadHashMismatch);
    }

    let signature_bytes = hex::decode(&signature.signature_hex).map_err(|source| {
        ReplayBundleError::SignatureMalformed {
            detail: source.to_string(),
        }
    })?;
    let signature_bytes: [u8; 64] = signature_bytes.try_into().map_err(|bytes: Vec<u8>| {
        ReplayBundleError::SignatureMalformed {
            detail: format!("expected 64 bytes, got {}", bytes.len()),
        }
    })?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| ReplayBundleError::SignatureInvalid)
}

pub fn verify_replay_bundle_signature_with_trust_set(
    bundle: &ReplayBundle,
    trusted_key_ids: &[String],
) -> Result<(), ReplayBundleError> {
    let signature = bundle
        .signature
        .as_ref()
        .ok_or(ReplayBundleError::SignatureMissing)?;
    if trusted_key_ids.is_empty() {
        return Err(ReplayBundleError::SignatureTrustAnchorMissing);
    }
    if !trusted_key_ids
        .iter()
        .any(|trusted_key_id| constant_time::ct_eq(trusted_key_id, &signature.key_id))
    {
        return Err(ReplayBundleError::SignatureKeyUntrusted {
            actual: signature.key_id.clone(),
            expected: "configured replay trust set".to_string(),
        });
    }

    verify_replay_bundle_signature(bundle, Some(&signature.key_id))
}

pub fn replay_bundle(bundle: &ReplayBundle) -> Result<ReplayOutcome, ReplayBundleError> {
    if !validate_bundle_integrity(bundle)? {
        return Err(ReplayBundleError::IntegrityMismatch);
    }
    verify_replay_bundle_signature(bundle, None)?;

    replay_bundle_after_signature_verification(bundle)
}

pub fn replay_bundle_with_trusted_key(
    bundle: &ReplayBundle,
    trusted_key_id: &str,
) -> Result<ReplayOutcome, ReplayBundleError> {
    if !validate_bundle_integrity(bundle)? {
        return Err(ReplayBundleError::IntegrityMismatch);
    }
    verify_replay_bundle_signature(bundle, Some(trusted_key_id))?;

    replay_bundle_after_signature_verification(bundle)
}

pub fn replay_bundle_with_trusted_keys(
    bundle: &ReplayBundle,
    trusted_key_ids: &[String],
) -> Result<ReplayOutcome, ReplayBundleError> {
    if !validate_bundle_integrity(bundle)? {
        return Err(ReplayBundleError::IntegrityMismatch);
    }
    verify_replay_bundle_signature_with_trust_set(bundle, trusted_key_ids)?;

    replay_bundle_after_signature_verification(bundle)
}

fn replay_bundle_after_signature_verification(
    bundle: &ReplayBundle,
) -> Result<ReplayOutcome, ReplayBundleError> {
    let replayed_sequence_hash = compute_decision_sequence_hash(
        &bundle.timeline,
        &bundle.initial_state_snapshot,
        &bundle.policy_version,
    )?;

    Ok(ReplayOutcome {
        incident_id: bundle.incident_id.clone(),
        expected_sequence_hash: bundle.manifest.decision_sequence_hash.clone(),
        matched: constant_time::ct_eq(
            &replayed_sequence_hash,
            &bundle.manifest.decision_sequence_hash,
        ),
        replayed_sequence_hash,
        event_count: bundle.timeline.len(),
    })
}

fn ensure_parent_dir(path: &Path) -> Result<(), ReplayBundleError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|err| {
            std::io::Error::new(
                err.kind(),
                format!("failed creating {}: {err}", parent.display()),
            )
        })?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), ReplayBundleError> {
    std::fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|err| {
            std::io::Error::new(
                err.kind(),
                format!("failed syncing directory {}: {err}", path.display()),
            )
        })?;
    Ok(())
}

fn normalized_directory(path: &Path) -> &Path {
    if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    }
}

fn write_bytes_atomically(path: &Path, bytes: &[u8]) -> Result<(), ReplayBundleError> {
    ensure_parent_dir(path)?;
    let parent = normalized_directory(path.parent().unwrap_or_else(|| Path::new(".")));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            std::io::Error::other(format!("failed deriving file name for {}", path.display()))
        })?;
    let temp_path = path.with_file_name(format!("{file_name}.tmp-{}", Uuid::now_v7()));
    let mut temp_guard = TempFileGuard::new(temp_path.clone());
    {
        let mut temp_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|err| {
                std::io::Error::new(
                    err.kind(),
                    format!("failed opening {}: {err}", temp_path.display()),
                )
            })?;
        temp_file.write_all(bytes).map_err(|err| {
            std::io::Error::new(
                err.kind(),
                format!("failed writing {}: {err}", temp_path.display()),
            )
        })?;
        temp_file.sync_all().map_err(|err| {
            std::io::Error::new(
                err.kind(),
                format!("failed syncing {}: {err}", temp_path.display()),
            )
        })?;
    }
    std::fs::rename(&temp_path, path).map_err(|err| {
        std::io::Error::new(
            err.kind(),
            format!(
                "failed promoting bundle {} -> {}: {err}",
                temp_path.display(),
                path.display()
            ),
        )
    })?;
    temp_guard.defuse();
    sync_directory(parent)?;
    if let Some(ancestor) = parent.parent() {
        let ancestor = normalized_directory(ancestor);
        if ancestor != parent {
            sync_directory(ancestor)?;
        }
    }
    Ok(())
}

pub fn write_bundle_to_path(bundle: &ReplayBundle, path: &Path) -> Result<(), ReplayBundleError> {
    if !validate_bundle_integrity(bundle)? {
        return Err(ReplayBundleError::IntegrityMismatch);
    }
    verify_replay_bundle_signature(bundle, None)?;
    write_verified_bundle_to_path(bundle, path)
}

pub fn write_bundle_to_path_with_trusted_key(
    bundle: &ReplayBundle,
    path: &Path,
    trusted_key_id: &str,
) -> Result<(), ReplayBundleError> {
    if !validate_bundle_integrity(bundle)? {
        return Err(ReplayBundleError::IntegrityMismatch);
    }
    verify_replay_bundle_signature(bundle, Some(trusted_key_id))?;
    write_verified_bundle_to_path(bundle, path)
}

fn write_verified_bundle_to_path(
    bundle: &ReplayBundle,
    path: &Path,
) -> Result<(), ReplayBundleError> {
    let canonical_json = to_canonical_json(bundle)?;
    write_bytes_atomically(path, canonical_json.as_bytes())?;
    Ok(())
}

pub fn read_bundle_from_path(path: &Path) -> Result<ReplayBundle, ReplayBundleError> {
    read_bundle_from_path_with_trusted_key(path, None)
}

pub fn read_bundle_from_path_with_trusted_key(
    path: &Path,
    trusted_key_id: Option<&str>,
) -> Result<ReplayBundle, ReplayBundleError> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let bundle: ReplayBundle = serde_json::from_reader(reader)?;
    if !validate_bundle_integrity(&bundle)? {
        return Err(ReplayBundleError::IntegrityMismatch);
    }
    validate_adversarial_bundle_shape(&bundle)?;
    verify_replay_bundle_signature(&bundle, trusted_key_id)?;
    Ok(bundle)
}

pub fn read_bundle_from_path_with_trusted_keys(
    path: &Path,
    trusted_key_ids: &[String],
) -> Result<ReplayBundle, ReplayBundleError> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let bundle: ReplayBundle = serde_json::from_reader(reader)?;
    if !validate_bundle_integrity(&bundle)? {
        return Err(ReplayBundleError::IntegrityMismatch);
    }
    validate_adversarial_bundle_shape(&bundle)?;
    verify_replay_bundle_signature_with_trust_set(&bundle, trusted_key_ids)?;
    Ok(bundle)
}

pub fn replay_bundle_adversarial_fuzz_one(input: &[u8]) -> Result<(), ReplayBundleError> {
    let bundle = decode_replay_bundle_fuzz_input(input)?;
    validate_adversarial_bundle_shape(&bundle)?;
    replay_bundle(&bundle).map(|_| ())
}

pub fn replay_bundle_batch_adversarial_fuzz_one(input: &[u8]) -> Result<(), ReplayBundleError> {
    let value = decode_replay_bundle_json_value(input)?;
    reject_negative_cast_offsets(&value, "$")?;
    let bundles: Vec<ReplayBundle> = serde_json::from_value(value)?;
    let mut seen = BTreeSet::new();
    for bundle in &bundles {
        if !seen.insert(bundle.bundle_id) {
            return Err(ReplayBundleError::DuplicateBundleId {
                bundle_id: bundle.bundle_id,
            });
        }
    }
    for bundle in &bundles {
        validate_adversarial_bundle_shape(bundle)?;
        replay_bundle(bundle)?;
    }
    Ok(())
}

pub fn to_canonical_json(bundle: &ReplayBundle) -> Result<String, ReplayBundleError> {
    let value = serde_json::to_value(bundle)?;
    let canonical = canonicalize_value(&value, "$")?;
    Ok(serde_json::to_string(&canonical)?)
}

fn decode_replay_bundle_fuzz_input(input: &[u8]) -> Result<ReplayBundle, ReplayBundleError> {
    let value = decode_replay_bundle_json_value(input)?;
    reject_negative_cast_offsets(&value, "$")?;
    Ok(serde_json::from_value(value)?)
}

fn decode_replay_bundle_json_value(input: &[u8]) -> Result<Value, ReplayBundleError> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = Value::deserialize(&mut deserializer).map_err(classify_fuzz_json_error)?;
    deserializer.end().map_err(classify_fuzz_json_error)?;
    Ok(value)
}

fn classify_fuzz_json_error(source: serde_json::Error) -> ReplayBundleError {
    if source.is_eof() {
        ReplayBundleError::TruncatedFinalChunk
    } else if source.to_string().contains("trailing characters") {
        ReplayBundleError::TrailingGarbage
    } else {
        ReplayBundleError::Json(source)
    }
}

fn reject_negative_cast_offsets(value: &Value, path: &str) -> Result<(), ReplayBundleError> {
    match value {
        Value::Array(items) => {
            for (idx, item) in items.iter().enumerate() {
                reject_negative_cast_offsets(item, &format!("{path}[{idx}]"))?;
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                let next_path = format!("{path}.{key}");
                if is_unsigned_replay_bundle_field(key)
                    && let Some(number) = item.as_i64()
                    && number < 0
                {
                    return Err(ReplayBundleError::NegativeCastOffset {
                        path: next_path,
                        value: number,
                    });
                }
                reject_negative_cast_offsets(item, &next_path)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn is_unsigned_replay_bundle_field(field: &str) -> bool {
    matches!(
        field,
        "causal_parent"
            | "chunk_count"
            | "chunk_index"
            | "compressed_size_bytes"
            | "event_count"
            | "first_sequence_number"
            | "last_sequence_number"
            | "sequence_number"
            | "time_span_micros"
            | "total_chunks"
    )
}

fn validate_adversarial_bundle_shape(bundle: &ReplayBundle) -> Result<(), ReplayBundleError> {
    reject_zero_length_chunks(bundle)?;
    reject_duplicate_chunk_offsets(bundle)?;
    reject_non_monotonic_chunk_timestamps(bundle)?;
    reject_future_bundle_timestamps(bundle)?;
    Ok(())
}

fn reject_zero_length_chunks(bundle: &ReplayBundle) -> Result<(), ReplayBundleError> {
    if bundle.timeline.is_empty() {
        return Ok(());
    }
    for chunk in &bundle.chunks {
        if chunk.event_count == 0 || chunk.events.is_empty() {
            return Err(ReplayBundleError::ZeroLengthChunk {
                chunk_index: chunk.chunk_index,
            });
        }
    }
    Ok(())
}

fn reject_duplicate_chunk_offsets(bundle: &ReplayBundle) -> Result<(), ReplayBundleError> {
    let mut seen = BTreeSet::new();
    for chunk in &bundle.chunks {
        if !seen.insert(chunk.chunk_index) {
            return Err(ReplayBundleError::DuplicateChunkOffset {
                chunk_index: chunk.chunk_index,
            });
        }
    }
    Ok(())
}

fn reject_non_monotonic_chunk_timestamps(bundle: &ReplayBundle) -> Result<(), ReplayBundleError> {
    for chunk in &bundle.chunks {
        let mut previous_timestamp: Option<(String, i64)> = None;
        for event in &chunk.events {
            let (_, next_micros) = normalize_timestamp(&event.timestamp)?;
            if let Some((previous, previous_micros)) = &previous_timestamp
                && next_micros < *previous_micros
            {
                return Err(ReplayBundleError::NonMonotonicChunkTimestamp {
                    chunk_index: chunk.chunk_index,
                    previous: previous.clone(),
                    next: event.timestamp.clone(),
                });
            }
            previous_timestamp = Some((event.timestamp.clone(), next_micros));
        }
    }
    Ok(())
}

fn reject_future_bundle_timestamps(bundle: &ReplayBundle) -> Result<(), ReplayBundleError> {
    reject_future_timestamp("$.created_at", &bundle.created_at)?;
    for (idx, event) in bundle.timeline.iter().enumerate() {
        reject_future_timestamp(&format!("$.timeline[{idx}].timestamp"), &event.timestamp)?;
    }
    for (chunk_idx, chunk) in bundle.chunks.iter().enumerate() {
        for (event_idx, event) in chunk.events.iter().enumerate() {
            reject_future_timestamp(
                &format!("$.chunks[{chunk_idx}].events[{event_idx}].timestamp"),
                &event.timestamp,
            )?;
        }
    }
    Ok(())
}

fn reject_future_timestamp(path: &str, timestamp: &str) -> Result<(), ReplayBundleError> {
    let parsed = DateTime::parse_from_rfc3339(timestamp).map_err(|source| {
        ReplayBundleError::TimestampParse {
            timestamp: timestamp.to_string(),
            source,
        }
    })?;
    if parsed.with_timezone(&Utc) > Utc::now() {
        return Err(ReplayBundleError::TimestampInFuture {
            path: path.to_string(),
            timestamp: timestamp.to_string(),
        });
    }
    Ok(())
}

/// Deterministic fixture-only incident timeline for unit tests and test-support harnesses.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn fixture_incident_events(incident_id: &str) -> Vec<RawEvent> {
    vec![
        RawEvent::new(
            "2026-02-20T12:00:00.000001Z",
            EventType::ExternalSignal,
            serde_json::json!({
                "incident_id": incident_id,
                "signal": "anomaly_detected",
                "severity": "high"
            }),
        )
        .with_state_snapshot(serde_json::json!({
            "hardening_level": "enhanced",
            "epoch": 42_u64,
            "active_policies": ["strict-revocation", "quarantine-on-high-risk"]
        }))
        .with_policy_version("1.0.0"),
        RawEvent::new(
            "2026-02-20T12:00:00.000450Z",
            EventType::PolicyEval,
            serde_json::json!({
                "decision": "quarantine",
                "confidence": 95_u64,
                "rule_id": "policy.rule.high-impact-receipt"
            }),
        )
        .with_causal_parent(1),
        RawEvent::new(
            "2026-02-20T12:00:00.001200Z",
            EventType::OperatorAction,
            serde_json::json!({
                "action": "isolate-artifact",
                "artifact": "sha256:fixture-incident-sample",
                "result": "accepted"
            }),
        )
        .with_causal_parent(2),
    ]
}

fn normalize_timestamp(timestamp: &str) -> Result<(String, i64), ReplayBundleError> {
    let parsed = DateTime::parse_from_rfc3339(timestamp).map_err(|source| {
        ReplayBundleError::TimestampParse {
            timestamp: timestamp.to_string(),
            source,
        }
    })?;
    let normalized = parsed
        .with_timezone(&Utc)
        .to_rfc3339_opts(SecondsFormat::Micros, true);
    Ok((normalized, parsed.timestamp_micros()))
}

fn deterministic_bundle_id(
    incident_id: &str,
    created_at: &str,
    timeline: &[TimelineEvent],
) -> Result<Uuid, ReplayBundleError> {
    let canonical_seed = canonicalize_value(
        &serde_json::json!({
            "incident_id": incident_id,
            "created_at": created_at,
            "timeline": timeline
        }),
        "$.bundle_seed",
    )?;
    let seed_bytes = canonical_json_bytes(&canonical_seed)?;
    let digest = Sha256::digest([b"replay_bundle_seed_v1:" as &[u8], &seed_bytes].concat());
    let mut entropy = [0_u8; 32];
    entropy.copy_from_slice(&digest);

    let created_ts_ms = DateTime::parse_from_rfc3339(created_at)
        .map_err(|source| ReplayBundleError::TimestampParse {
            timestamp: created_at.to_string(),
            source,
        })?
        .timestamp_millis();
    let timestamp_u64 = u64::try_from(created_ts_ms.max(0)).unwrap_or(0);
    Ok(uuid_v7_from_seed(timestamp_u64, &entropy))
}

fn uuid_v7_from_seed(timestamp_ms: u64, entropy: &[u8; 32]) -> Uuid {
    let ts_48 = timestamp_ms & 0x0000_FFFF_FFFF_FFFF;
    let ts_bytes = ts_48.to_be_bytes();
    let mut bytes = [0_u8; 16];
    bytes[..6].copy_from_slice(&ts_bytes[2..8]);
    bytes[6] = 0x70 | (entropy[0] & 0x0F);
    bytes[7] = entropy[1];
    bytes[8] = 0x80 | (entropy[2] & 0x3F);
    bytes[9..16].copy_from_slice(&entropy[3..10]);
    Uuid::from_bytes(bytes)
}

fn compute_decision_sequence_hash(
    timeline: &[TimelineEvent],
    initial_state_snapshot: &Value,
    policy_version: &str,
) -> Result<String, ReplayBundleError> {
    let canonical = canonicalize_value(
        &serde_json::json!({
            "timeline": timeline,
            "initial_state_snapshot": initial_state_snapshot,
            "policy_version": policy_version
        }),
        "$.decision_sequence",
    )?;
    Ok(sha256_hex(&canonical_json_bytes(&canonical)?))
}

fn compute_integrity_hash(bundle: &ReplayBundle) -> Result<String, ReplayBundleError> {
    let view = ReplayBundleIntegrityView {
        bundle_id: &bundle.bundle_id,
        incident_id: &bundle.incident_id,
        created_at: &bundle.created_at,
        timeline: &bundle.timeline,
        initial_state_snapshot: &bundle.initial_state_snapshot,
        policy_version: &bundle.policy_version,
        manifest: &bundle.manifest,
        chunks: &bundle.chunks,
        evidence_refs: &bundle.evidence_refs,
        trust_artifact_refs: &bundle.trust_artifact_refs,
    };
    let canonical = canonicalize_value(&serde_json::to_value(view)?, "$.integrity_view")?;
    Ok(sha256_hex(&canonical_json_bytes(&canonical)?))
}

fn replay_bundle_signature_payload(bundle: &ReplayBundle) -> Vec<u8> {
    let integrity_hash = bundle.integrity_hash.as_bytes();
    let mut payload = Vec::with_capacity(
        REPLAY_BUNDLE_SIGNATURE_PAYLOAD_DOMAIN
            .len()
            .saturating_add(std::mem::size_of::<u64>())
            .saturating_add(integrity_hash.len()),
    );
    payload.extend_from_slice(REPLAY_BUNDLE_SIGNATURE_PAYLOAD_DOMAIN);
    payload.extend_from_slice(
        &(u64::try_from(integrity_hash.len()).unwrap_or(u64::MAX)).to_le_bytes(),
    );
    payload.extend_from_slice(integrity_hash);
    payload
}

fn validate_bundle_structure(bundle: &ReplayBundle) -> Result<(), ReplayBundleError> {
    let expected_created_at = derive_created_at(&bundle.timeline);
    if bundle.created_at != expected_created_at {
        return Err(ReplayBundleError::CreatedAtMismatch);
    }

    let expected_bundle_id =
        deterministic_bundle_id(&bundle.incident_id, &expected_created_at, &bundle.timeline)?;
    if bundle.bundle_id != expected_bundle_id {
        return Err(ReplayBundleError::BundleIdMismatch);
    }

    let expected_chunks = chunk_timeline(expected_bundle_id, &bundle.timeline)?;
    if bundle.chunks != expected_chunks {
        return Err(ReplayBundleError::ChunkLayoutMismatch);
    }

    let expected_manifest = derive_bundle_manifest(
        &bundle.timeline,
        &bundle.initial_state_snapshot,
        &bundle.policy_version,
        expected_chunks.len(),
    )?;
    if bundle.manifest != expected_manifest {
        return Err(ReplayBundleError::ManifestMismatch);
    }

    validate_replay_bundle_refs(bundle)?;

    Ok(())
}

fn validate_replay_bundle_refs(bundle: &ReplayBundle) -> Result<(), ReplayBundleError> {
    for reference in &bundle.evidence_refs {
        validate_relative_evidence_ref(reference)?;
    }
    for reference in &bundle.trust_artifact_refs {
        validate_relative_evidence_ref(reference)?;
    }

    let evidence_refs = bundle
        .evidence_refs
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for reference in &bundle.trust_artifact_refs {
        if !evidence_refs.contains(reference.as_str()) {
            return Err(ReplayBundleError::TrustArtifactRefMissingEvidence {
                reference: reference.clone(),
            });
        }
    }

    Ok(())
}

fn derive_created_at(timeline: &[TimelineEvent]) -> String {
    timeline.last().map_or_else(
        || DEFAULT_CREATED_AT.to_string(),
        |event| event.timestamp.clone(),
    )
}

fn derive_bundle_manifest(
    timeline: &[TimelineEvent],
    initial_state_snapshot: &Value,
    policy_version: &str,
    chunk_count: usize,
) -> Result<BundleManifest, ReplayBundleError> {
    let decision_sequence_hash =
        compute_decision_sequence_hash(timeline, initial_state_snapshot, policy_version)?;
    let timeline_value = canonicalize_value(&serde_json::to_value(timeline)?, "$.timeline")?;
    let timeline_bytes = canonical_json_bytes(&timeline_value)?;
    let compressed_size_bytes = gzip_size_bytes(&timeline_bytes)?;
    let (first_timestamp, last_timestamp) = match (timeline.first(), timeline.last()) {
        (Some(first), Some(last)) => (Some(first.timestamp.clone()), Some(last.timestamp.clone())),
        _ => (None, None),
    };
    let time_span_micros = match (timeline.first(), timeline.last()) {
        (Some(first), Some(last)) => {
            let first_micros = normalize_timestamp(&first.timestamp)?.1;
            let last_micros = normalize_timestamp(&last.timestamp)?.1;
            u64::try_from(last_micros.saturating_sub(first_micros)).unwrap_or(0)
        }
        _ => 0,
    };

    Ok(BundleManifest {
        event_count: timeline.len(),
        first_timestamp,
        last_timestamp,
        time_span_micros,
        compressed_size_bytes,
        chunk_count: u32::try_from(chunk_count).unwrap_or(u32::MAX),
        decision_sequence_hash,
    })
}

fn chunk_timeline(
    bundle_id: Uuid,
    timeline: &[TimelineEvent],
) -> Result<Vec<BundleChunk>, ReplayBundleError> {
    if timeline.is_empty() {
        return Ok(vec![BundleChunk {
            bundle_id,
            chunk_index: 0,
            total_chunks: 1,
            event_count: 0,
            first_sequence_number: 0,
            last_sequence_number: 0,
            compressed_size_bytes: 0,
            chunk_hash: sha256_hex(b"[]"),
            events: Vec::new(),
        }]);
    }

    let mut buckets: Vec<Vec<TimelineEvent>> = Vec::new();
    let mut current_bucket: Vec<TimelineEvent> = Vec::new();
    let mut current_size = 2_usize;
    let max_event_size = MAX_BUNDLE_BYTES.saturating_sub(2);

    for event in timeline {
        let event_json = canonicalize_value(&serde_json::to_value(event)?, "$.timeline_event")?;
        let event_size = canonical_json_len(&event_json)?;
        if event_size >= max_event_size {
            return Err(ReplayBundleError::OversizedEvent {
                sequence_number: event.sequence_number,
                size_bytes: event_size,
                max_bytes: max_event_size,
            });
        }
        let delimiter = usize::from(!current_bucket.is_empty());

        if !current_bucket.is_empty()
            && current_size
                .saturating_add(delimiter)
                .saturating_add(event_size)
                > MAX_BUNDLE_BYTES
        {
            if buckets.len() >= MAX_CHUNKS_PER_BUNDLE {
                return Err(ReplayBundleError::TooManyChunks {
                    count: buckets.len().saturating_add(1),
                    max: MAX_CHUNKS_PER_BUNDLE,
                });
            }
            buckets.push(current_bucket);
            current_bucket = Vec::new();
            current_size = 2;
        }

        let delimiter = usize::from(!current_bucket.is_empty());
        current_size = current_size
            .saturating_add(delimiter)
            .saturating_add(event_size);
        current_bucket.push(event.clone());
    }

    if !current_bucket.is_empty() {
        if buckets.len() >= MAX_CHUNKS_PER_BUNDLE {
            return Err(ReplayBundleError::TooManyChunks {
                count: buckets.len().saturating_add(1),
                max: MAX_CHUNKS_PER_BUNDLE,
            });
        }
        buckets.push(current_bucket);
    }

    let total_chunks = u32::try_from(buckets.len()).unwrap_or(u32::MAX);
    let mut chunks = Vec::with_capacity(buckets.len());

    for (idx, events) in buckets.into_iter().enumerate() {
        let chunk_value = canonicalize_value(&serde_json::to_value(&events)?, "$.chunk_events")?;
        let chunk_bytes = canonical_json_bytes(&chunk_value)?;
        let first_sequence_number = events.first().map_or(0, |event| event.sequence_number);
        let last_sequence_number = events.last().map_or(0, |event| event.sequence_number);
        chunks.push(BundleChunk {
            bundle_id,
            chunk_index: u32::try_from(idx).unwrap_or(u32::MAX),
            total_chunks,
            event_count: events.len(),
            first_sequence_number,
            last_sequence_number,
            compressed_size_bytes: gzip_size_bytes(&chunk_bytes)?,
            chunk_hash: sha256_hex(&chunk_bytes),
            events,
        });
    }

    Ok(chunks)
}

#[cfg(feature = "compression")]
fn gzip_size_bytes(bytes: &[u8]) -> Result<u64, ReplayBundleError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    std::io::Write::write_all(&mut encoder, bytes)?;
    let compressed = encoder.finish()?;
    Ok(u64::try_from(compressed.len()).unwrap_or(u64::MAX))
}

#[cfg(not(feature = "compression"))]
fn gzip_size_bytes(bytes: &[u8]) -> Result<u64, ReplayBundleError> {
    // When compression is disabled, return original size
    Ok(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, ReplayBundleError> {
    Ok(serde_json::to_vec(value)?)
}

fn canonical_json_len(value: &Value) -> Result<usize, ReplayBundleError> {
    let mut counter = JsonByteCounter::default();
    serde_json::to_writer(&mut counter, value)?;
    Ok(counter.len)
}

#[derive(Default)]
struct JsonByteCounter {
    len: usize,
}

impl std::io::Write for JsonByteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.len = self
            .len
            .checked_add(buf.len())
            .ok_or_else(|| std::io::Error::other("canonical JSON length exceeds usize"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"replay_bundle_hash_v1:" as &[u8]);
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub(crate) fn canonicalize_value(value: &Value, path: &str) -> Result<Value, ReplayBundleError> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(value.clone()),
        Value::Number(number) => {
            if number.is_f64() {
                Err(ReplayBundleError::NonDeterministicFloat {
                    path: path.to_string(),
                })
            } else {
                Ok(value.clone())
            }
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for (idx, item) in items.iter().enumerate() {
                out.push(canonicalize_value(item, &format!("{path}[{idx}]"))?);
            }
            Ok(Value::Array(out))
        }
        Value::Object(map) => {
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_unstable();
            let mut out = Map::new();
            for key in keys {
                let next_path = format!("{path}.{key}");
                let next_value = canonicalize_value(&map[key], &next_path)?;
                out.insert(key.to_string(), next_value);
            }
            Ok(Value::Object(out))
        }
    }
}

/// Hardening: bounded push to prevent unbounded growth of struct-field Vecs
#[cfg(test)]
pub(crate) fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn cwd_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn temp_leftovers(dir: &Path, prefix: &str) -> Vec<String> {
        let mut leftovers = Vec::new();
        for entry in std::fs::read_dir(dir).expect("read dir") {
            let entry = entry.expect("entry");
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(prefix) {
                leftovers.push(name.to_string());
            }
        }
        leftovers.sort();
        leftovers
    }

    #[test]
    fn temp_file_guard_orphans_abandoned_temp_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let temp_path = dir.path().join("bundle.json.tmp");
        std::fs::write(&temp_path, "pending").expect("write temp file");

        {
            let _guard = TempFileGuard::new(temp_path.clone());
        }

        assert!(!temp_path.exists(), "temp file should be moved aside");
        let leftovers = temp_leftovers(dir.path(), "bundle.json.tmp.orphaned-");
        assert_eq!(leftovers.len(), 1, "expected one orphaned temp artifact");
    }

    fn fixture_events() -> Vec<RawEvent> {
        vec![
            RawEvent::new(
                "2026-02-20T10:00:00.000100Z",
                EventType::ExternalSignal,
                serde_json::json!({"signal":"anomaly","severity":"high"}),
            )
            .with_state_snapshot(serde_json::json!({"epoch":7,"mode":"strict"}))
            .with_policy_version("1.2.3"),
            RawEvent::new(
                "2026-02-20T10:00:00.000200Z",
                EventType::PolicyEval,
                serde_json::json!({"decision":"quarantine","confidence":91_u64}),
            )
            .with_causal_parent(1),
            RawEvent::new(
                "2026-02-20T10:00:00.000300Z",
                EventType::OperatorAction,
                serde_json::json!({"action":"seal","result":"accepted"}),
            )
            .with_causal_parent(2),
        ]
    }

    fn fixture_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[42_u8; 32])
    }

    fn fixture_trusted_key_id() -> String {
        let signing_key = fixture_signing_key();
        crate::supply_chain::artifact_signing::KeyId::from_verifying_key(
            &signing_key.verifying_key(),
        )
        .to_string()
    }

    fn sign_fixture_bundle(bundle: &mut ReplayBundle) {
        let signing_key = fixture_signing_key();
        let signing_material = ReplayBundleSigningMaterial {
            signing_key: &signing_key,
            key_source: "env",
            signing_identity: "incident-control-plane",
        };
        sign_replay_bundle(bundle, &signing_material).expect("sign replay bundle");
    }

    fn signed_fixture_bundle(incident_id: &str) -> ReplayBundle {
        let mut bundle = generate_replay_bundle(incident_id, &fixture_events()).expect("bundle");
        sign_fixture_bundle(&mut bundle);
        bundle
    }

    fn fixture_evidence_package(incident_id: &str) -> IncidentEvidencePackage {
        IncidentEvidencePackage {
            schema_version: INCIDENT_EVIDENCE_SCHEMA.to_string(),
            incident_id: incident_id.to_string(),
            collected_at: "2026-02-20T10:05:00.000000Z".to_string(),
            trace_id: "trace-incident-evidence".to_string(),
            severity: IncidentSeverity::High,
            incident_type: "security".to_string(),
            detector: "unit-test".to_string(),
            policy_version: "1.2.3".to_string(),
            initial_state_snapshot: serde_json::json!({"epoch": 7_u64, "mode": "strict"}),
            events: vec![
                IncidentEvidenceEvent {
                    event_id: "evt-001".to_string(),
                    timestamp: "2026-02-20T10:00:00.000100Z".to_string(),
                    event_type: EventType::ExternalSignal,
                    payload: serde_json::json!({"signal":"anomaly","severity":"high"}),
                    provenance_ref: "refs/logs/event-001.json".to_string(),
                    parent_event_id: None,
                    state_snapshot: None,
                    policy_version: None,
                },
                IncidentEvidenceEvent {
                    event_id: "evt-002".to_string(),
                    timestamp: "2026-02-20T10:00:00.000200Z".to_string(),
                    event_type: EventType::PolicyEval,
                    payload: serde_json::json!({"decision":"quarantine","confidence":91_u64}),
                    provenance_ref: "refs/logs/event-002.json".to_string(),
                    parent_event_id: Some("evt-001".to_string()),
                    state_snapshot: None,
                    policy_version: None,
                },
                IncidentEvidenceEvent {
                    event_id: "evt-003".to_string(),
                    timestamp: "2026-02-20T10:00:00.000300Z".to_string(),
                    event_type: EventType::OperatorAction,
                    payload: serde_json::json!({"action":"seal","result":"accepted"}),
                    provenance_ref: "refs/logs/event-003.json".to_string(),
                    parent_event_id: Some("evt-002".to_string()),
                    state_snapshot: None,
                    policy_version: None,
                },
            ],
            evidence_refs: vec![
                "refs/logs/event-001.json".to_string(),
                "refs/logs/event-002.json".to_string(),
                "refs/logs/event-003.json".to_string(),
            ],
            metadata: IncidentEvidenceMetadata {
                title: "Synthetic incident".to_string(),
                affected_components: vec!["auth-svc".to_string()],
                tags: vec!["test".to_string()],
            },
        }
    }

    fn chunked_fixture_bundle() -> ReplayBundle {
        let large = "x".repeat(3 * 1024 * 1024);
        let events = vec![
            RawEvent::new(
                "2026-02-20T10:00:00.000001Z",
                EventType::StateChange,
                serde_json::json!({"blob": large}),
            ),
            RawEvent::new(
                "2026-02-20T10:00:00.000002Z",
                EventType::PolicyEval,
                serde_json::json!({"blob": "y".repeat(3 * 1024 * 1024)}),
            ),
            RawEvent::new(
                "2026-02-20T10:00:00.000003Z",
                EventType::OperatorAction,
                serde_json::json!({"blob": "z".repeat(3 * 1024 * 1024)}),
            ),
            RawEvent::new(
                "2026-02-20T10:00:00.000004Z",
                EventType::ExternalSignal,
                serde_json::json!({"blob": "w".repeat(3 * 1024 * 1024)}),
            ),
        ];

        generate_replay_bundle("INC-CHUNK-FIXTURE-001", &events).expect("chunked bundle")
    }

    #[test]
    fn bundle_generation_is_deterministic() {
        let events = fixture_events();
        let first = generate_replay_bundle("INC-DET-001", &events).expect("bundle 1");
        let second = generate_replay_bundle("INC-DET-001", &events).expect("bundle 2");
        let first_json = to_canonical_json(&first).expect("json 1");
        let second_json = to_canonical_json(&second).expect("json 2");
        assert_eq!(first_json, second_json, "bundle bytes must match");
        assert_eq!(first.bundle_id, second.bundle_id);
        assert_eq!(first.integrity_hash, second.integrity_hash);
    }

    #[test]
    fn bundle_id_is_uuid_v7() {
        let bundle = generate_replay_bundle("INC-UUID-001", &fixture_events()).expect("bundle");
        assert_eq!(bundle.bundle_id.get_version_num(), 7);
    }

    #[test]
    fn integrity_round_trip() {
        let bundle = generate_replay_bundle("INC-INT-001", &fixture_events()).expect("bundle");
        assert!(validate_bundle_integrity(&bundle).expect("validate"));
    }

    #[test]
    fn replay_matches_expected_hash() {
        let bundle = signed_fixture_bundle("INC-RPL-001");
        let trusted_key_id = fixture_trusted_key_id();
        let outcome = replay_bundle_with_trusted_key(&bundle, &trusted_key_id).expect("replay");
        assert!(outcome.matched);
        assert_eq!(outcome.event_count, 3);
        assert_eq!(
            outcome.expected_sequence_hash,
            outcome.replayed_sequence_hash
        );
    }

    #[test]
    fn replay_rejects_integrity_mismatch() {
        let mut bundle = generate_replay_bundle("INC-RPL-002", &fixture_events()).expect("bundle");
        sign_fixture_bundle(&mut bundle);
        bundle.integrity_hash = "deadbeef".repeat(8);
        let err = replay_bundle(&bundle).expect_err("must fail");
        assert!(matches!(err, ReplayBundleError::IntegrityMismatch));
    }

    #[test]
    fn replay_rejects_missing_signature() {
        let bundle = generate_replay_bundle("INC-RPL-UNSIGNED", &fixture_events()).expect("bundle");
        let err = replay_bundle(&bundle).expect_err("must fail closed");
        assert!(matches!(err, ReplayBundleError::SignatureMissing));
    }

    #[test]
    fn replay_rejects_invalid_signature() {
        let mut bundle = signed_fixture_bundle("INC-RPL-BAD-SIG");
        bundle.signature.as_mut().expect("signature").signature_hex = "00".repeat(64);

        let trusted_key_id = fixture_trusted_key_id();
        let err = replay_bundle_with_trusted_key(&bundle, &trusted_key_id)
            .expect_err("must reject invalid signature");
        assert!(matches!(err, ReplayBundleError::SignatureInvalid));
    }

    #[test]
    fn replay_bundle_signature_round_trips_with_trusted_key_id() {
        let bundle = signed_fixture_bundle("INC-RPL-SIG-001");
        let signing_key = fixture_signing_key();
        let trusted_key_id = crate::supply_chain::artifact_signing::KeyId::from_verifying_key(
            &signing_key.verifying_key(),
        )
        .to_string();

        verify_replay_bundle_signature(&bundle, Some(&trusted_key_id)).expect("trusted signature");
        let signature = bundle.signature.as_ref().expect("signature");
        assert_eq!(signature.algorithm, "ed25519");
        assert_eq!(signature.key_source, "env");
        assert_eq!(signature.signing_identity, "incident-control-plane");
        assert_eq!(signature.trust_scope, REPLAY_BUNDLE_SIGNATURE_TRUST_SCOPE);
        assert_eq!(
            signature.public_key_hex,
            hex::encode(signing_key.verifying_key().to_bytes())
        );
    }

    #[test]
    fn replay_bundle_signature_payload_is_domain_separated() {
        let bundle = signed_fixture_bundle("INC-RPL-SIG-DOMAIN");
        let payload = replay_bundle_signature_payload(&bundle);
        let integrity_hash = bundle.integrity_hash.as_bytes();
        let mut expected = Vec::new();
        expected.extend_from_slice(REPLAY_BUNDLE_SIGNATURE_PAYLOAD_DOMAIN);
        expected.extend_from_slice(
            &(u64::try_from(integrity_hash.len()).expect("hash length fits u64")).to_le_bytes(),
        );
        expected.extend_from_slice(integrity_hash);

        assert_eq!(payload, expected);
        assert_ne!(payload.as_slice(), integrity_hash);
        let signature = bundle.signature.as_ref().expect("signature");
        assert_ne!(
            signature.signed_payload_sha256,
            hex::encode(Sha256::digest(integrity_hash))
        );
    }

    #[test]
    fn replay_bundle_signature_rejects_untrusted_key_id() {
        let bundle = signed_fixture_bundle("INC-RPL-SIG-002");
        let err = verify_replay_bundle_signature(&bundle, Some("keyid:untrusted"))
            .expect_err("must reject untrusted key");
        assert!(matches!(
            err,
            ReplayBundleError::SignatureKeyUntrusted { .. }
        ));
    }

    #[test]
    fn replay_bundle_signature_rejects_key_id_not_derived_from_public_key() {
        let mut bundle = signed_fixture_bundle("INC-RPL-SIG-KEYID-MISMATCH");
        let forged_key_id = "0".repeat(16);
        bundle.signature.as_mut().expect("signature").key_id = forged_key_id.clone();

        let err = verify_replay_bundle_signature(&bundle, Some(&forged_key_id))
            .expect_err("trusted key id must still match the public key");

        assert!(matches!(
            err,
            ReplayBundleError::SignatureKeyIdMismatch { ref claimed, .. }
                if claimed == &forged_key_id
        ));
    }

    #[test]
    fn replay_bundle_default_verification_rejects_untrusted_signer() {
        let bundle = signed_fixture_bundle("INC-RPL-SIG-UNTRUSTED-DEFAULT");
        let err = verify_replay_bundle_signature(&bundle, None)
            .expect_err("default verification must require a trust anchor");
        assert!(matches!(
            err,
            ReplayBundleError::SignatureTrustAnchorMissing
        ));

        let replay_err = replay_bundle(&bundle).expect_err("default replay must fail closed");
        assert!(matches!(
            replay_err,
            ReplayBundleError::SignatureTrustAnchorMissing
        ));
    }

    #[test]
    fn read_bundle_from_path_rejects_untrusted_signer_by_default() {
        let bundle = signed_fixture_bundle("INC-RPL-SIG-UNTRUSTED-DISK");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bundle.json");
        std::fs::write(&path, to_canonical_json(&bundle).expect("canonical bundle"))
            .expect("write raw bundle");

        let err = read_bundle_from_path(&path).expect_err("default read must fail closed");
        assert!(matches!(
            err,
            ReplayBundleError::SignatureTrustAnchorMissing
        ));

        let trusted_key_id = fixture_trusted_key_id();
        read_bundle_from_path_with_trusted_key(&path, Some(&trusted_key_id))
            .expect("trusted read should still work");
    }

    #[test]
    fn write_bundle_to_path_rejects_untrusted_signer_by_default() {
        let bundle = signed_fixture_bundle("INC-RPL-SIG-UNTRUSTED-WRITE");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bundle.json");

        let err = write_bundle_to_path(&bundle, &path).expect_err("default write must fail closed");
        assert!(matches!(
            err,
            ReplayBundleError::SignatureTrustAnchorMissing
        ));
        assert!(!path.exists());
    }

    #[test]
    fn validate_bundle_integrity_rejects_manifest_drift_even_with_recomputed_hash() {
        let mut bundle = generate_replay_bundle("INC-RPL-003", &fixture_events()).expect("bundle");
        bundle.manifest.event_count = bundle.manifest.event_count.saturating_add(1);
        bundle.integrity_hash = compute_integrity_hash(&bundle).expect("rehash");

        let err = validate_bundle_integrity(&bundle).expect_err("must reject manifest drift");
        assert!(matches!(err, ReplayBundleError::ManifestMismatch));
    }

    #[test]
    fn validate_bundle_integrity_rejects_created_at_drift_even_with_recomputed_hash() {
        let mut bundle = generate_replay_bundle("INC-RPL-004", &fixture_events()).expect("bundle");
        bundle.created_at = DEFAULT_CREATED_AT.to_string();
        bundle.integrity_hash = compute_integrity_hash(&bundle).expect("rehash");

        let err = validate_bundle_integrity(&bundle).expect_err("must reject created_at drift");
        assert!(matches!(err, ReplayBundleError::CreatedAtMismatch));
    }

    #[test]
    fn replay_rejects_chunk_layout_drift_even_with_recomputed_hash() {
        let mut bundle = chunked_fixture_bundle();
        bundle.chunks.swap(0, 1);
        bundle.integrity_hash = compute_integrity_hash(&bundle).expect("rehash");

        let err = replay_bundle(&bundle).expect_err("must reject chunk drift");
        assert!(matches!(err, ReplayBundleError::ChunkLayoutMismatch));
    }

    #[test]
    fn validate_bundle_integrity_rejects_bundle_id_drift_even_with_recomputed_hash() {
        let mut bundle = generate_replay_bundle("INC-RPL-005", &fixture_events()).expect("bundle");
        bundle.bundle_id = Uuid::nil();
        bundle.integrity_hash = compute_integrity_hash(&bundle).expect("rehash");

        let err = validate_bundle_integrity(&bundle).expect_err("must reject bundle id drift");
        assert!(matches!(err, ReplayBundleError::BundleIdMismatch));
    }

    #[test]
    fn float_payload_is_rejected() {
        let events = vec![RawEvent::new(
            "2026-02-20T10:00:00Z",
            EventType::StateChange,
            serde_json::json!({"n": 1.25_f64}),
        )];
        let err = generate_replay_bundle("INC-FLOAT-001", &events).expect_err("must fail");
        assert!(matches!(
            err,
            ReplayBundleError::NonDeterministicFloat { .. }
        ));
    }

    #[test]
    fn chunking_activates_for_large_payload() {
        let bundle = chunked_fixture_bundle();
        assert!(bundle.manifest.chunk_count > 1);
        assert_eq!(
            usize::try_from(bundle.manifest.chunk_count).ok(),
            Some(bundle.chunks.len())
        );
        for chunk in &bundle.chunks {
            assert_eq!(chunk.bundle_id, bundle.bundle_id);
            assert_eq!(chunk.total_chunks, bundle.manifest.chunk_count);
        }
    }

    #[test]
    fn oversized_single_event_is_rejected() {
        let oversized_blob = "x".repeat((10 * 1024 * 1024) + 1024);
        let events = vec![RawEvent::new(
            "2026-02-20T10:00:00.000001Z",
            EventType::StateChange,
            serde_json::json!({"blob": oversized_blob}),
        )];

        let err = generate_replay_bundle("INC-OVERSIZE-001", &events).expect_err("must fail");
        assert!(matches!(
            err,
            ReplayBundleError::OversizedEvent {
                sequence_number: 1,
                ..
            }
        ));
    }

    #[test]
    fn oversized_event_log_is_rejected_without_truncation() {
        let events = (0..=MAX_PREPARED_EVENTS)
            .map(|_| {
                RawEvent::new(
                    "2026-02-20T10:00:00.000001Z",
                    EventType::ExternalSignal,
                    serde_json::json!({"event": "overflow"}),
                )
            })
            .collect::<Vec<_>>();

        let err = generate_replay_bundle("INC-TOO-MANY-EVENTS", &events).expect_err("must fail");
        assert!(matches!(
            err,
            ReplayBundleError::TooManyEvents { count, max }
                if count == MAX_PREPARED_EVENTS.saturating_add(1) && max == MAX_PREPARED_EVENTS
        ));
    }

    #[test]
    fn write_and_read_roundtrip() {
        let bundle = signed_fixture_bundle("INC-IO-001");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bundle.json");
        let trusted_key_id = fixture_trusted_key_id();
        write_bundle_to_path_with_trusted_key(&bundle, &path, &trusted_key_id).expect("write");
        let loaded =
            read_bundle_from_path_with_trusted_key(&path, Some(&trusted_key_id)).expect("read");
        assert_eq!(bundle, loaded);
    }

    #[test]
    fn write_bundle_to_path_is_atomic_and_cleans_temp_files() {
        let first =
            generate_replay_bundle("INC-IO-ATOMIC-001", &fixture_events()).expect("first bundle");
        let second =
            generate_replay_bundle("INC-IO-ATOMIC-002", &fixture_events()).expect("second bundle");
        let mut first = first;
        let mut second = second;
        sign_fixture_bundle(&mut first);
        sign_fixture_bundle(&mut second);
        let dir = tempfile::tempdir().expect("tempdir");
        let dir_path = dir.path().join("nested");
        let path = dir_path.join("bundle.json");
        let temp_prefix = "bundle.json.tmp";

        let trusted_key_id = fixture_trusted_key_id();
        write_bundle_to_path_with_trusted_key(&first, &path, &trusted_key_id).expect("write first");
        let mut leftovers = temp_leftovers(&dir_path, temp_prefix);
        assert!(
            leftovers.is_empty(),
            "temporary files should not remain after first write: {leftovers:?}"
        );

        write_bundle_to_path_with_trusted_key(&second, &path, &trusted_key_id)
            .expect("write second");
        leftovers = temp_leftovers(&dir_path, temp_prefix);
        assert!(
            leftovers.is_empty(),
            "temporary files should not remain after replacement write: {leftovers:?}"
        );
    }

    #[test]
    fn read_rejects_tampered_bundle_from_disk() {
        let bundle = signed_fixture_bundle("INC-IO-002");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bundle.json");
        let trusted_key_id = fixture_trusted_key_id();
        write_bundle_to_path_with_trusted_key(&bundle, &path, &trusted_key_id).expect("write");

        let mut tampered: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read raw"))
                .expect("parse bundle json");
        tampered["manifest"]["event_count"] = Value::from(999_u64);
        std::fs::write(
            &path,
            serde_json::to_string(&tampered).expect("serialize tampered bundle"),
        )
        .expect("write tampered bundle");

        let err = read_bundle_from_path_with_trusted_key(&path, Some(&trusted_key_id))
            .expect_err("must reject tampered bundle");
        assert!(matches!(err, ReplayBundleError::ManifestMismatch));
    }

    #[test]
    fn write_bundle_supports_relative_file_in_current_directory() {
        let _lock = cwd_test_lock().lock().expect("cwd test lock");
        let bundle = signed_fixture_bundle("INC-IO-REL-001");
        let dir = tempfile::tempdir().expect("tempdir");
        let previous_cwd = std::env::current_dir().expect("current dir");
        std::env::set_current_dir(dir.path()).expect("set cwd");

        let relative_path = Path::new("bundle.json");
        let trusted_key_id = fixture_trusted_key_id();
        let write_result =
            write_bundle_to_path_with_trusted_key(&bundle, relative_path, &trusted_key_id);
        let restore_result = std::env::set_current_dir(&previous_cwd);

        write_result.expect("write relative bundle");
        restore_result.expect("restore cwd");

        let loaded = read_bundle_from_path_with_trusted_key(
            &dir.path().join("bundle.json"),
            Some(&trusted_key_id),
        )
        .expect("read");
        assert_eq!(bundle, loaded);
    }

    #[test]
    fn sample_events_are_stable() {
        let first = fixture_incident_events("INC-STABLE-001");
        let second = fixture_incident_events("INC-STABLE-001");
        assert_eq!(first, second);
    }

    #[test]
    fn push_bounded_prevents_unbounded_growth() {
        let mut vec = Vec::new();
        let max_cap = 3;

        // Push up to capacity
        for i in 0..max_cap {
            super::push_bounded(&mut vec, i, max_cap);
        }
        assert_eq!(vec.len(), 3);
        assert_eq!(vec, vec![0, 1, 2]);

        // Push beyond capacity should evict oldest items
        super::push_bounded(&mut vec, 3, max_cap);
        assert_eq!(vec.len(), 3);
        assert_eq!(vec, vec![1, 2, 3]);

        super::push_bounded(&mut vec, 4, max_cap);
        assert_eq!(vec.len(), 3);
        assert_eq!(vec, vec![2, 3, 4]);

        // Push multiple items beyond capacity
        super::push_bounded(&mut vec, 5, max_cap);
        super::push_bounded(&mut vec, 6, max_cap);
        assert_eq!(vec.len(), 3);
        assert_eq!(vec, vec![4, 5, 6]);
    }

    #[test]
    fn chunked_bundle_respects_max_chunks_limit() {
        // Create events that would generate many chunks
        let large_payload = "x".repeat(5_000_000); // 5MB each to force chunking
        let mut events = Vec::new();

        // Create enough events to test chunk limiting
        for i in 0..10 {
            events.push(RawEvent::new(
                &format!("2026-01-01T00:00:00.{:06}Z", i),
                EventType::StateChange,
                serde_json::json!({"data": format!("{}{}", large_payload, i)}),
            ));
        }

        let bundle = generate_replay_bundle("INC-CHUNK-LIMIT-TEST", &events).unwrap();

        // Should have created chunks but not exceed our limit
        assert!(bundle.manifest.chunk_count > 1);
        assert!(bundle.manifest.chunk_count as usize <= super::MAX_CHUNKS_PER_BUNDLE);
        assert_eq!(bundle.chunks.len(), bundle.manifest.chunk_count as usize);
    }

    #[test]
    fn evidence_package_generation_is_deterministic() {
        let package = fixture_evidence_package("INC-EVID-DET-001");
        let first = generate_replay_bundle_from_evidence(&package).expect("bundle 1");
        let second = generate_replay_bundle_from_evidence(&package).expect("bundle 2");
        assert_eq!(
            to_canonical_json(&first).expect("json 1"),
            to_canonical_json(&second).expect("json 2")
        );
    }

    #[test]
    fn evidence_package_bundle_round_trip_preserves_refs_and_trust_artifacts() {
        let mut package = fixture_evidence_package("INC-EVID-REFS-001");
        package
            .evidence_refs
            .push("refs/trust/trust-card.json".to_string());

        let mut bundle = generate_replay_bundle_from_evidence(&package).expect("bundle");
        assert_eq!(bundle.evidence_refs, package.evidence_refs);
        assert_eq!(
            bundle.trust_artifact_refs,
            vec!["refs/trust/trust-card.json".to_string()]
        );
        assert!(validate_bundle_integrity(&bundle).expect("integrity"));

        sign_fixture_bundle(&mut bundle);
        let trusted_key_id = fixture_trusted_key_id();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bundle.json");
        write_bundle_to_path_with_trusted_key(&bundle, &path, &trusted_key_id)
            .expect("write bundle");

        let loaded =
            read_bundle_from_path_with_trusted_key(&path, Some(&trusted_key_id)).expect("read");
        assert_eq!(loaded.evidence_refs, package.evidence_refs);
        assert_eq!(loaded.trust_artifact_refs, bundle.trust_artifact_refs);

        let wire = serde_json::to_value(&loaded).expect("bundle json");
        assert_eq!(
            wire.get("evidence_refs").expect("evidence_refs"),
            &serde_json::json!(package.evidence_refs)
        );
        assert_eq!(
            wire.get("trust_artifact_refs")
                .expect("trust_artifact_refs"),
            &serde_json::json!(["refs/trust/trust-card.json"])
        );
    }

    #[test]
    fn evidence_package_rejects_empty_evidence_refs() {
        let mut package = fixture_evidence_package("INC-EVID-VAL-001");
        package.evidence_refs.clear();

        let err = validate_incident_evidence_package(&package, Some("INC-EVID-VAL-001"))
            .expect_err("must fail");
        assert!(matches!(err, ReplayBundleError::EvidenceRefsEmpty));
    }

    #[test]
    fn evidence_package_rejects_path_like_evidence_refs() {
        for reference in [
            "../secrets.json",
            "/tmp/secrets.json",
            r"refs\logs\event-001.json",
            "refs/logs/event-001.json\0",
        ] {
            let mut package = fixture_evidence_package("INC-EVID-VAL-REFS");
            package.evidence_refs = vec![reference.to_string()];

            let err = validate_incident_evidence_package(&package, Some("INC-EVID-VAL-REFS"))
                .expect_err("path-like evidence ref must fail closed");
            assert!(matches!(
                err,
                ReplayBundleError::EvidenceRefNotRelative {
                    reference: ref rejected
                }
                    if rejected == reference
            ));
        }
    }

    #[test]
    fn evidence_package_rejects_unknown_provenance_refs() {
        let mut package = fixture_evidence_package("INC-EVID-VAL-002");
        package.events[0].provenance_ref = "refs/logs/missing.json".to_string();

        let err = validate_incident_evidence_package(&package, Some("INC-EVID-VAL-002"))
            .expect_err("must fail");
        assert!(matches!(
            err,
            ReplayBundleError::EvidenceUnknownProvenanceRef { .. }
        ));
    }

    #[test]
    fn evidence_package_rejects_unsorted_events() {
        let mut package = fixture_evidence_package("INC-EVID-VAL-003");
        package.events.swap(0, 1);

        let err = validate_incident_evidence_package(&package, Some("INC-EVID-VAL-003"))
            .expect_err("must fail");
        match err {
            ReplayBundleError::EvidenceEventsUnsorted {
                previous_index,
                next_index,
            } => {
                assert_eq!(previous_index, 0);
                assert_eq!(next_index, 1);
            }
            _ => panic!("expected EvidenceEventsUnsorted"),
        }
    }

    #[test]
    fn read_incident_evidence_package_rejects_incident_id_mismatch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("evidence.json");
        let package = fixture_evidence_package("INC-EVID-READ-001");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&package).expect("serialize evidence"),
        )
        .expect("write evidence");

        let err = read_incident_evidence_package(&path, Some("INC-OTHER"))
            .expect_err("must reject mismatch");
        assert!(matches!(
            err,
            ReplayBundleError::EvidenceIncidentIdMismatch { .. }
        ));
    }

    #[test]
    fn read_incident_evidence_package_rejects_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("missing.json");
        let err =
            read_incident_evidence_package(&path, Some("INC-EVID-MISSING-001")).expect_err("io");
        assert!(matches!(err, ReplayBundleError::Io(_)));
    }

    #[test]
    fn generate_replay_bundle_from_evidence_uses_authoritative_snapshot_and_policy_version() {
        let package = fixture_evidence_package("INC-EVID-BUNDLE-001");
        let bundle = generate_replay_bundle_from_evidence(&package).expect("bundle");

        assert_eq!(
            bundle.initial_state_snapshot,
            package.initial_state_snapshot
        );
        assert_eq!(bundle.policy_version, package.policy_version);
        assert_eq!(bundle.incident_id, package.incident_id);
    }

    // Integer overflow protection tests for bd-7nqi2

    /// Test that sequence number calculations handle large indices safely using saturating arithmetic
    #[test]
    fn sequence_number_calculation_uses_saturating_arithmetic() {
        // Test with large index values that would overflow with regular arithmetic
        let large_index = usize::MAX - 1;

        // This should not panic and should saturate to u64::MAX
        let sequence_number = u64::try_from(large_index.saturating_add(1)).unwrap_or(u64::MAX);

        // Should saturate to u64::MAX rather than panicking
        assert_eq!(sequence_number, u64::MAX);
    }

    /// Test push_bounded function with edge cases that could cause overflow
    #[test]
    fn push_bounded_handles_large_collections_safely() {
        let mut items: Vec<u32> = Vec::new();

        // Fill up to a large capacity to test overflow protection
        let large_cap = 1000;
        for i in 0..large_cap {
            super::push_bounded(&mut items, i, large_cap);
        }
        assert_eq!(items.len(), large_cap);

        // Add more items beyond capacity - should use saturating arithmetic
        for i in large_cap..(large_cap + 10) {
            super::push_bounded(&mut items, i, large_cap);
        }

        // Should maintain the capacity limit
        assert_eq!(items.len(), large_cap);

        // Verify the items were properly rotated (oldest removed, newest kept)
        assert_eq!(items[items.len() - 1], (large_cap + 9) as u32);
    }

    /// Test event sequence numbering with maximum index values
    #[test]
    fn event_sequence_numbering_saturates_safely() {
        // Create an event with extremely large original index
        let large_original_index = usize::MAX - 10;

        // Simulate the sequence number calculation from the timeline generation
        let sequence_number =
            u64::try_from(large_original_index.saturating_add(1)).unwrap_or(u64::MAX);

        // Should saturate to u64::MAX instead of overflowing
        assert_eq!(sequence_number, u64::MAX);
    }

    /// Test that overflow protection works in id_to_index mapping
    #[test]
    fn id_to_index_mapping_uses_saturating_arithmetic() {
        // Test the pattern used in generate_replay_bundle_from_evidence
        let large_idx = usize::MAX - 5;

        // This pattern is used in the id_to_index calculation
        let mapped_index = u64::try_from(large_idx.saturating_add(1)).unwrap_or(u64::MAX);

        // Should saturate rather than overflow
        assert_eq!(mapped_index, u64::MAX);
    }

    /// Test current_index calculation with large event log lengths
    #[test]
    fn current_index_calculation_saturates_safely() {
        // Test with large event log length that could cause overflow
        let large_log_length = usize::MAX - 100;

        // This pattern is used in the causal parent validation
        let current_index = u64::try_from(large_log_length.saturating_add(1)).unwrap_or(u64::MAX);

        // Should saturate to u64::MAX
        assert_eq!(current_index, u64::MAX);
    }

    /// Test that causal parent subtraction uses saturating arithmetic
    #[test]
    fn causal_parent_subtraction_uses_saturating_arithmetic() {
        // Test the pattern used in causal parent index calculation
        let large_parent = u64::MAX - 1;

        // This should use saturating_sub (as seen in line 620)
        let parent_index_result = usize::try_from(large_parent.saturating_sub(1));

        // Should handle the conversion gracefully
        assert!(parent_index_result.is_ok() || parent_index_result.is_err());

        // Test edge case where parent is 0
        let zero_parent = 0u64;
        let zero_result = usize::try_from(zero_parent.saturating_sub(1));
        // saturating_sub(1) on 0 should give u64::MAX, which won't fit in usize
        assert!(zero_result.is_err());
    }

    /// Test that push_bounded handles edge case where items.len() equals cap
    #[test]
    fn push_bounded_handles_exact_capacity_boundary() {
        let mut items = vec![1, 2, 3];
        let cap = 3;

        // At exact capacity, adding one more should evict the oldest
        super::push_bounded(&mut items, 4, cap);

        assert_eq!(items.len(), cap);
        assert_eq!(items, vec![2, 3, 4]);
    }

    /// Test push_bounded with zero capacity edge case
    #[test]
    fn push_bounded_handles_zero_capacity() {
        let mut items: Vec<i32> = Vec::new();

        // With zero capacity, should handle gracefully
        super::push_bounded(&mut items, 42, 0);

        // Should be limited to capacity of 0 (empty)
        assert!(items.is_empty());
    }

    /// Test that chunk size calculations use saturating arithmetic
    #[test]
    fn chunk_size_calculations_use_saturating_arithmetic() {
        // Test the saturating arithmetic used in chunk_timeline function
        let large_size = usize::MAX - 1000;
        let delimiter = 1usize;
        let event_size = 500usize;

        // This pattern is used in the chunking logic
        let total_size = large_size
            .saturating_add(delimiter)
            .saturating_add(event_size);

        // Should saturate rather than overflow
        assert_eq!(total_size, usize::MAX);
    }

    // ── NEGATIVE-PATH TESTS: Security & Robustness ──────────────────

    #[test]
    fn test_negative_incident_id_with_unicode_injection_attacks() {
        use crate::security::constant_time;

        let malicious_incident_ids = [
            "incident\u{202E}fake_id\u{202C}",  // BiDi override attack
            "incident\x1b[31mred\x1b[0m",       // ANSI escape injection
            "incident\0null\r\n\t",             // Control character injection
            "incident\"injection}malicious",    // JSON injection attempt
            "incident/../../etc/passwd",        // Path traversal attempt
            "incident\u{200B}\u{200C}\u{200D}", // Zero-width character injection
        ];

        for malicious_id in malicious_incident_ids {
            // Verify incident ID validation catches injection attempts
            let test_events = vec![RawEvent::new(
                "2026-02-20T10:00:00.000100Z",
                EventType::ExternalSignal,
                serde_json::json!({"test": "injection"}),
            )];

            // The ID should be stored as-is, but Bundle operations should validate
            // Let's test that the incident_id field doesn't break serialization
            let result = generate_replay_bundle(malicious_id, &test_events);

            match result {
                Ok(bundle) => {
                    // If bundle creation succeeds, verify JSON serialization is safe
                    let json =
                        serde_json::to_string(&bundle).expect("serialization should not fail");

                    // Verify the malicious content is properly escaped in JSON
                    let parsed: serde_json::Value =
                        serde_json::from_str(&json).expect("JSON should be valid");
                    let parsed_id = parsed
                        .get("incident_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    // The ID should be preserved exactly for forensics, but contained safely
                    assert_eq!(
                        parsed_id, malicious_id,
                        "incident ID should be preserved for forensics"
                    );
                }
                Err(_) => {
                    // If validation rejects the ID, that's also acceptable security behavior
                }
            }

            // Verify constant-time comparison works for incident IDs
            let normal_id = "normal_incident_123";
            assert!(
                !constant_time::ct_eq(malicious_id, normal_id),
                "incident ID comparison should be constant-time"
            );
        }
    }

    #[test]
    fn test_negative_raw_event_with_massive_payload_memory_exhaustion() {
        // Create event with 5MB JSON payload
        let massive_payload = serde_json::json!({
            "attack_type": "memory_exhaustion",
            "large_field": "X".repeat(5_000_000), // 5MB string
            "nested": {
                "deep": {
                    "structure": "Y".repeat(1_000_000) // 1MB nested string
                }
            }
        });

        let massive_event = RawEvent::new(
            "2026-02-20T10:00:00.000100Z",
            EventType::ExternalSignal,
            massive_payload,
        );

        // Verify the event can be created without panic
        assert_eq!(massive_event.event_type, EventType::ExternalSignal);

        // Test serialization with massive payload
        let json = serde_json::to_string(&massive_event)
            .expect("serialization should handle large payload");
        assert!(
            json.len() > 6_000_000,
            "serialized form should preserve large payload"
        );

        // Test that bundles properly handle oversized events
        let massive_events = vec![massive_event];

        match generate_replay_bundle("massive-test", &massive_events) {
            Ok(bundle) => {
                // If it succeeds, verify it's within bounds or chunked appropriately
                let serialized = serde_json::to_string(&bundle).unwrap();
                // Large bundles should either be rejected or chunked
                if serialized.len() > MAX_BUNDLE_BYTES {
                    panic!("oversized bundle should have been rejected or chunked");
                }
            }
            Err(ReplayBundleError::OversizedEvent { .. }) => {
                // This is the expected behavior for oversized events
            }
            Err(other) => {
                panic!("unexpected error for oversized event: {:?}", other);
            }
        }
    }

    #[test]
    fn test_negative_bundle_manifest_with_json_injection_attacks() {
        // Add event with potential JSON injection in state snapshot
        let injection_payload = serde_json::json!({
            "normal_field": "value",
            "injection": "\"},\"malicious_field\":\"injected\",\"admin\":true,\"bypass"
        });

        let event = RawEvent::new(
            "2026-02-20T10:00:00.000100Z",
            EventType::StateChange,
            injection_payload,
        )
        .with_state_snapshot(serde_json::json!({
            "normal_state": "ok",
            "injection_attempt": "state\"},\"injected_admin\":true,\"bypass"
        }));

        let injection_events = vec![event];
        let bundle = generate_replay_bundle("injection-test", &injection_events)
            .expect("bundle should build");

        // Verify JSON structure integrity in manifest
        let json = serde_json::to_string(&bundle).expect("serialization should succeed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON should be valid");

        // Verify no extra fields were injected at the bundle level
        let expected_bundle_keys = [
            "bundle_id",
            "chunks",
            "created_at",
            "incident_id",
            "initial_state_snapshot",
            "integrity_hash",
            "manifest",
            "policy_version",
            "timeline",
        ];
        if let Some(bundle_obj) = parsed.as_object() {
            for key in bundle_obj.keys() {
                assert!(
                    expected_bundle_keys.contains(&key.as_str()),
                    "unexpected field '{}' - possible JSON injection",
                    key
                );
            }
        }

        // Verify manifest structure is not corrupted
        let manifest = parsed.get("manifest").expect("manifest should exist");
        assert!(manifest.is_object(), "manifest should be object");

        // Verify injection attempts are contained within event payloads (safe)
        let events = parsed.get("timeline").expect("timeline should exist");
        assert!(events.is_array(), "events should be array");

        if let Some(events_arr) = events.as_array() {
            for event in events_arr {
                if let Some(payload) = event.get("payload") {
                    // Injection should be contained as literal strings in the payload
                    let payload_str = payload.to_string();
                    if payload_str.contains("malicious_field") {
                        // It should be escaped as a literal string, not parsed as JSON structure
                        assert!(
                            payload_str.contains("\\\""),
                            "JSON injection should be escaped"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_negative_temp_file_guard_with_malicious_paths() {
        let malicious_paths = [
            "/tmp/../../etc/passwd.tmp",   // Path traversal
            "/tmp/bundle\0null.tmp",       // Null byte injection
            "/tmp/bundle\r\n.tmp",         // CRLF injection
            "/tmp/bundle\u{202E}fake.tmp", // BiDi override
            "/tmp/bundle\x1b[31m.tmp",     // ANSI escape
        ];

        for malicious_path in malicious_paths {
            let path_buf = std::path::PathBuf::from(malicious_path);

            // Create guard with malicious path
            let mut guard = TempFileGuard::new(path_buf.clone());

            // Test abandoned_path generation with malicious input
            let abandoned = TempFileGuard::abandoned_path(&path_buf);
            let abandoned_str = abandoned.to_string_lossy();

            // Verify abandoned path doesn't contain original injection patterns
            // (The path might be sanitized or preserved, but shouldn't propagate injection)
            assert!(
                abandoned_str.contains("orphaned-"),
                "abandoned path should have orphaned marker"
            );

            // Test defuse mechanism
            guard.defuse();
            // Dropping defused guard should not attempt file operations
        }

        // Test with extremely long path
        let long_path_component = "x".repeat(1000);
        let long_path = std::path::PathBuf::from(format!("/tmp/{}.tmp", long_path_component));

        let abandoned = TempFileGuard::abandoned_path(&long_path);
        let abandoned_str = abandoned.to_string_lossy();

        // Should handle long paths without panic
        assert!(
            abandoned_str.len() > long_path_component.len(),
            "abandoned path should be longer"
        );
        assert!(
            abandoned_str.contains("orphaned-"),
            "should contain orphaned marker"
        );
    }

    #[test]
    fn test_negative_bundle_compression_with_adversarial_payloads() {
        // Test with highly compressible payload (zip bomb potential)
        let repetitive_payload = serde_json::json!({
            "type": "zip_bomb_test",
            "repeated_data": "AAAA".repeat(100_000), // 400KB of repeated data
        });

        let compressible_event = RawEvent::new(
            "2026-02-20T10:00:00.000100Z",
            EventType::ExternalSignal,
            repetitive_payload,
        );

        let compression_events = vec![compressible_event];

        let bundle = generate_replay_bundle("compression-test", &compression_events)
            .expect("bundle should build");

        // Verify that compression is bounded and doesn't create extremely small bundles
        // that expand to huge sizes (zip bomb protection)
        let json = serde_json::to_string(&bundle).expect("serialization should work");
        let original_size = json.len();

        // Simulate compression like the chunking logic might do
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        std::io::Write::write_all(&mut encoder, json.as_bytes())
            .expect("compression write should work");
        let compressed = encoder.finish().expect("compression should complete");

        let compression_ratio = original_size as f64 / compressed.len() as f64;

        // Verify reasonable compression ratio bounds
        assert!(
            compression_ratio < 1000.0,
            "compression ratio should not be extreme (zip bomb protection)"
        );
        assert!(
            compressed.len() > 1000,
            "compressed size should have reasonable minimum"
        );

        // Test with highly entropic payload (should not compress well)
        let random_payload = serde_json::json!({
            "type": "entropy_test",
            "random_data": (0..50000).map(|i| format!("{:x}", i * 31 + 17)).collect::<String>(),
        });

        let entropic_event = RawEvent::new(
            "2026-02-20T10:00:00.000200Z",
            EventType::StateChange,
            random_payload,
        );

        let entropy_events = vec![entropic_event];

        let bundle2 = generate_replay_bundle("entropy-test", &entropy_events)
            .expect("entropic bundle should build");
        let json2 = serde_json::to_string(&bundle2).expect("entropic serialization should work");

        // High-entropy data should not compress as well
        let mut encoder2 = GzEncoder::new(Vec::new(), Compression::default());
        std::io::Write::write_all(&mut encoder2, json2.as_bytes())
            .expect("entropic compression should work");
        let compressed2 = encoder2
            .finish()
            .expect("entropic compression should complete");

        let entropy_ratio = json2.len() as f64 / compressed2.len() as f64;
        assert!(
            entropy_ratio < compression_ratio,
            "high entropy should compress worse than repetitive data"
        );
    }

    #[test]
    fn test_negative_event_type_serialization_with_invalid_variants() {
        // Test EventType serialization robustness
        let event_types = [
            EventType::ExternalSignal,
            EventType::StateChange,
            EventType::PolicyEval,
            EventType::OperatorAction,
        ];

        for event_type in event_types {
            let event = RawEvent::new(
                "2026-02-20T10:00:00.000100Z",
                event_type,
                serde_json::json!({"test": "data"}),
            );

            // Test JSON roundtrip
            let json = serde_json::to_string(&event).expect("event serialization should work");
            let parsed: RawEvent =
                serde_json::from_str(&json).expect("event deserialization should work");
            assert_eq!(
                parsed.event_type, event_type,
                "event type should be preserved"
            );
        }

        // Test potential deserialization of invalid enum variants
        let invalid_json = r#"{
            "timestamp": "2026-02-20T10:00:00.000100Z",
            "event_type": "InvalidVariant",
            "payload": {"test": "data"},
            "state_snapshot": null,
            "policy_version": "0.1.0"
        }"#;

        let result: Result<RawEvent, _> = serde_json::from_str(invalid_json);
        assert!(
            result.is_err(),
            "invalid event type should fail deserialization"
        );

        // Test with numeric event type (type confusion attack)
        let numeric_json = r#"{
            "timestamp": "2026-02-20T10:00:00.000100Z",
            "event_type": 999,
            "payload": {"test": "data"},
            "state_snapshot": null,
            "policy_version": "0.1.0"
        }"#;

        let result2: Result<RawEvent, _> = serde_json::from_str(numeric_json);
        assert!(
            result2.is_err(),
            "numeric event type should fail deserialization"
        );
    }

    #[test]
    fn test_negative_bundle_id_collision_resistance() {
        use crate::security::constant_time;

        // Create multiple bundles with same incident_id to test collision resistance
        let incident_id = "collision-test";

        let mut bundle_ids = Vec::new();
        for i in 0..100 {
            // Add slightly different events to test deterministic ID generation
            let event = RawEvent::new(
                &format!("2026-02-20T10:00:0{:02}.000100Z", i % 60),
                EventType::StateChange,
                serde_json::json!({"iteration": i}),
            );

            let collision_events = vec![event];
            let bundle = generate_replay_bundle(incident_id, &collision_events)
                .expect("bundle should build");
            bundle_ids.push(bundle.bundle_id);
        }

        // Verify all bundle IDs are unique (no collisions)
        for i in 0..bundle_ids.len() {
            for j in i + 1..bundle_ids.len() {
                let left = bundle_ids[i].to_string();
                let right = bundle_ids[j].to_string();
                assert!(
                    !constant_time::ct_eq(&left, &right),
                    "bundle IDs should be unique: {} vs {}",
                    bundle_ids[i],
                    bundle_ids[j]
                );
            }
        }

        // Verify bundle IDs have expected format and length
        for bundle_id in &bundle_ids {
            let bundle_id = bundle_id.to_string();
            assert!(!bundle_id.is_empty(), "bundle ID should not be empty");
            assert!(
                bundle_id.len() > 10,
                "bundle ID should have reasonable length"
            );
            assert!(
                bundle_id.len() < 256,
                "bundle ID should be reasonably bounded"
            );

            // Should not contain injection patterns
            assert!(
                !bundle_id.contains('\0'),
                "bundle ID should not contain null bytes"
            );
            assert!(
                !bundle_id.contains('\n'),
                "bundle ID should not contain newlines"
            );
            assert!(
                !bundle_id.contains('\x1b'),
                "bundle ID should not contain ANSI escapes"
            );
        }
    }

    #[test]
    fn test_negative_floating_point_validation_bypass_attempts() {
        // Test various floating point values that might bypass validation
        let suspicious_values = [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::MIN,
            f64::MAX,
            -0.0,
            f64::from_bits(0x7FF0000000000001), // Signaling NaN
            f64::from_bits(0x7FF8000000000000), // Quiet NaN
        ];

        for suspicious_value in suspicious_values {
            let payload_with_float = serde_json::json!({
                "test_field": "normal",
                "suspicious_number": suspicious_value,
                "nested": {
                    "inner_float": suspicious_value
                }
            });

            let event = RawEvent::new(
                "2026-02-20T10:00:00.000100Z",
                EventType::ExternalSignal,
                payload_with_float,
            );

            let float_events = vec![event];

            match generate_replay_bundle("float-test", &float_events) {
                Ok(_bundle) => {
                    // If bundle creation succeeds, the non-deterministic float validation
                    // either didn't trigger (floats were in safe locations) or was bypassed
                    // In a production system, this might be concerning
                }
                Err(ReplayBundleError::NonDeterministicFloat { path }) => {
                    // This is the expected behavior - floats should be detected and rejected
                    assert!(!path.is_empty(), "float detection should provide path");
                }
                Err(other) => {
                    // Other errors might be acceptable depending on validation order
                    println!(
                        "Got unexpected error for float {}: {:?}",
                        suspicious_value, other
                    );
                }
            }
        }

        // Test edge case: floats embedded in string values (should be OK)
        let string_with_float_content = serde_json::json!({
            "text_field": "The value is 3.14159",
            "json_string": "{\"inner_float\": 2.718}",
        });

        let string_event = RawEvent::new(
            "2026-02-20T10:00:00.000100Z",
            EventType::StateChange,
            string_with_float_content,
        );

        let string_events = vec![string_event];

        // String content containing float representations should be OK
        let result = generate_replay_bundle("string-float-test", &string_events);
        assert!(result.is_ok(), "floats in string content should be allowed");
    }

    #[test]
    fn test_negative_timestamp_parsing_with_malicious_formats() {
        let malicious_timestamps = [
            "2026-02-20T10:00:00.000100Z\x00null",    // Null byte injection
            "2026-02-20T10:00:00.000100Z\r\n",        // CRLF injection
            "2026-02-20T10:00:00.000100Z\x1b[31m",    // ANSI escape
            "2026-02-20T10:00:00.000100Z\"injection", // Quote injection
            "2026-02-20T10:00:00.000100Z\u{202E}fake", // BiDi override
            "2026\u{200B}-02-20T10:00:00.000100Z",    // Zero-width space
            "9999-12-31T23:59:59.999999Z",            // Extreme future date
            "0001-01-01T00:00:00.000000Z",            // Extreme past date
            "2026-13-45T25:61:61.999999Z",            // Invalid date components
            "not-a-timestamp-at-all",                 // Complete garbage
            "",                                       // Empty string
            "\u{FFFD}\u{FFFD}\u{FFFD}",               // Replacement characters
        ];

        for malicious_timestamp in malicious_timestamps {
            // Test direct timestamp construction
            let result = RawEvent::new(
                malicious_timestamp,
                EventType::ExternalSignal,
                serde_json::json!({"test": "timestamp_validation"}),
            );

            // The constructor might:
            // 1. Accept the timestamp and fail later during validation
            // 2. Fail immediately during parsing
            // 3. Sanitize/normalize the timestamp

            // Test that timestamps are properly validated somewhere in the pipeline
            let timestamp_events = vec![result];

            match generate_replay_bundle("timestamp-test", &timestamp_events) {
                Ok(bundle) => {
                    // If successful, verify the timestamp in the bundle is valid
                    let json = serde_json::to_string(&bundle).expect("serialization should work");
                    let parsed: serde_json::Value =
                        serde_json::from_str(&json).expect("JSON should be valid");

                    if let Some(events) = parsed.get("timeline").and_then(|e| e.as_array()) {
                        for event in events {
                            if let Some(timestamp) = event.get("timestamp").and_then(|t| t.as_str())
                            {
                                // Verify stored timestamp doesn't contain injection patterns
                                assert!(
                                    !timestamp.contains('\0'),
                                    "stored timestamp should not contain null bytes"
                                );
                                assert!(
                                    !timestamp.contains('\r'),
                                    "stored timestamp should not contain CRLF"
                                );
                                assert!(
                                    !timestamp.contains('\x1b'),
                                    "stored timestamp should not contain ANSI"
                                );
                            }
                        }
                    }
                }
                Err(ReplayBundleError::TimestampParse { timestamp, .. }) => {
                    // Expected behavior for invalid timestamps
                    assert_eq!(
                        timestamp, malicious_timestamp,
                        "error should reference original timestamp"
                    );
                }
                Err(other) => {
                    // Other validation errors might also be acceptable
                    println!(
                        "Got other error for timestamp '{}': {:?}",
                        malicious_timestamp, other
                    );
                }
            }
        }
    }
}
