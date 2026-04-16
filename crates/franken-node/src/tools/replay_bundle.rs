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
use std::path::Path;

use chrono::{DateTime, SecondsFormat, Utc};
use flate2::{Compression, write::GzEncoder};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const MAX_BUNDLE_BYTES: usize = 10 * 1024 * 1024;
const MAX_CHUNKS_PER_BUNDLE: usize = 1000; // Hardening: prevent unbounded chunk growth
const MAX_EVENT_LOG: usize = 50000; // Hardening: prevent unbounded event log growth
const MAX_PREPARED_EVENTS: usize = 50000; // Hardening: prevent unbounded prepared events
const DEFAULT_POLICY_VERSION: &str = "0.1.0";
const DEFAULT_CREATED_AT: &str = "1970-01-01T00:00:00.000000Z";
pub const INCIDENT_EVIDENCE_SCHEMA: &str = "franken-node/incident-evidence-source/v1";

/// RAII guard that orphans a temp file on drop (unless defused after rename).
#[must_use]
struct TempFileGuard(Option<std::path::PathBuf>);

impl TempFileGuard {
    fn new(path: std::path::PathBuf) -> Self {
        Self(Some(path))
    }

    fn abandoned_path(path: &Path) -> std::path::PathBuf {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("replay-bundle.json.tmp");
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
            let _ = std::fs::rename(&path, Self::abandoned_path(&path));
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
    #[error("json serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bundle created_at does not match canonical timeline derivation")]
    CreatedAtMismatch,
    #[error("bundle id does not match canonical incident/timeline derivation")]
    BundleIdMismatch,
    #[error("bundle manifest does not match canonical timeline derivation")]
    ManifestMismatch,
    #[error("bundle chunks do not match canonical timeline derivation")]
    ChunkLayoutMismatch,
    #[error("bundle integrity mismatch")]
    IntegrityMismatch,
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
    pub integrity_hash: String,
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
                let current_index = u64::try_from(event_log.len().saturating_add(1)).unwrap_or(u64::MAX);
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
        push_bounded(&mut event_log, RawEvent {
            timestamp: event.timestamp,
            event_type: event.event_type,
            payload: event.payload,
            causal_parent,
            state_snapshot: event.state_snapshot,
            policy_version: None,
        }, MAX_EVENT_LOG);
    }

    if let Some(first) = event_log.first_mut() {
        first.state_snapshot = Some(package.initial_state_snapshot.clone());
        first.policy_version = Some(selected_policy_version);
    }

    generate_replay_bundle(&package.incident_id, &event_log)
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

    let mut prepared: Vec<PreparedEvent> = Vec::with_capacity(event_log.len());
    for (idx, event) in event_log.iter().enumerate() {
        let (normalized_timestamp, timestamp_micros) = normalize_timestamp(&event.timestamp)?;
        let payload = canonicalize_value(&event.payload, "$.payload")?;
        let payload_hash = sha256_hex(&canonical_json_bytes(&payload)?);
        let state_snapshot = match &event.state_snapshot {
            Some(snapshot) => Some(canonicalize_value(snapshot, "$.state_snapshot")?),
            None => None,
        };
        push_bounded(&mut prepared, PreparedEvent {
            normalized_timestamp,
            timestamp_micros,
            event_type: event.event_type,
            payload,
            _payload_hash: payload_hash,
            causal_parent: event.causal_parent,
            state_snapshot,
            policy_version: event.policy_version.clone(),
            original_index: idx,
        }, MAX_PREPARED_EVENTS);
    }

    prepared.sort_by(|left, right| {
        left.timestamp_micros
            .cmp(&right.timestamp_micros)
            .then_with(|| left.original_index.cmp(&right.original_index))
    });

    let mut original_to_new = vec![0_u64; event_log.len()];
    for (new_index, event) in prepared.iter().enumerate() {
        original_to_new[event.original_index] = u64::try_from(new_index.saturating_add(1)).unwrap_or(u64::MAX);
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
        integrity_hash: String::new(),
    };

    bundle.integrity_hash = compute_integrity_hash(&bundle)?;
    Ok(bundle)
}

pub fn validate_bundle_integrity(bundle: &ReplayBundle) -> Result<bool, ReplayBundleError> {
    validate_bundle_structure(bundle)?;
    let recomputed = compute_integrity_hash(bundle)?;
    Ok(crate::security::constant_time::ct_eq(
        &recomputed,
        &bundle.integrity_hash,
    ))
}

pub fn replay_bundle(bundle: &ReplayBundle) -> Result<ReplayOutcome, ReplayBundleError> {
    if !validate_bundle_integrity(bundle)? {
        return Err(ReplayBundleError::IntegrityMismatch);
    }

    let replayed_sequence_hash = compute_decision_sequence_hash(
        &bundle.timeline,
        &bundle.initial_state_snapshot,
        &bundle.policy_version,
    )?;

    Ok(ReplayOutcome {
        incident_id: bundle.incident_id.clone(),
        expected_sequence_hash: bundle.manifest.decision_sequence_hash.clone(),
        matched: crate::security::constant_time::ct_eq(
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

fn write_bytes_atomically(path: &Path, bytes: &[u8]) -> Result<(), ReplayBundleError> {
    ensure_parent_dir(path)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            std::io::Error::other(format!("failed deriving file name for {}", path.display()))
        })?;
    let temp_path = path.with_file_name(format!("{file_name}.tmp-{}", Uuid::now_v7()));
    let mut temp_guard = TempFileGuard::new(temp_path.clone());
    std::fs::write(&temp_path, bytes).map_err(|err| {
        std::io::Error::new(
            err.kind(),
            format!("failed writing {}: {err}", temp_path.display()),
        )
    })?;
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
    Ok(())
}

pub fn write_bundle_to_path(bundle: &ReplayBundle, path: &Path) -> Result<(), ReplayBundleError> {
    if !validate_bundle_integrity(bundle)? {
        return Err(ReplayBundleError::IntegrityMismatch);
    }
    let canonical_json = to_canonical_json(bundle)?;
    write_bytes_atomically(path, canonical_json.as_bytes())?;
    Ok(())
}

pub fn read_bundle_from_path(path: &Path) -> Result<ReplayBundle, ReplayBundleError> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let bundle: ReplayBundle = serde_json::from_reader(reader)?;
    if !validate_bundle_integrity(&bundle)? {
        return Err(ReplayBundleError::IntegrityMismatch);
    }
    Ok(bundle)
}

pub fn to_canonical_json(bundle: &ReplayBundle) -> Result<String, ReplayBundleError> {
    let value = serde_json::to_value(bundle)?;
    let canonical = canonicalize_value(&value, "$")?;
    Ok(serde_json::to_string(&canonical)?)
}

/// Deterministic fixture-only incident timeline for unit tests and examples.
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
    };
    let canonical = canonicalize_value(&serde_json::to_value(view)?, "$.integrity_view")?;
    Ok(sha256_hex(&canonical_json_bytes(&canonical)?))
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
        let event_size = canonical_json_bytes(&event_json)?.len();
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
            push_bounded(&mut buckets, current_bucket, MAX_CHUNKS_PER_BUNDLE);
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
        push_bounded(&mut buckets, current_bucket, MAX_CHUNKS_PER_BUNDLE);
    }

    let total_chunks = u32::try_from(buckets.len()).unwrap_or(u32::MAX);
    let mut chunks = Vec::with_capacity(buckets.len());

    for (idx, events) in buckets.into_iter().enumerate() {
        let chunk_value = canonicalize_value(&serde_json::to_value(&events)?, "$.chunk_events")?;
        let chunk_bytes = canonical_json_bytes(&chunk_value)?;
        let first_sequence_number = events.first().map_or(0, |event| event.sequence_number);
        let last_sequence_number = events.last().map_or(0, |event| event.sequence_number);
        push_bounded(&mut chunks, BundleChunk {
            bundle_id,
            chunk_index: u32::try_from(idx).unwrap_or(u32::MAX),
            total_chunks,
            event_count: events.len(),
            first_sequence_number,
            last_sequence_number,
            compressed_size_bytes: gzip_size_bytes(&chunk_bytes)?,
            chunk_hash: sha256_hex(&chunk_bytes),
            events,
        }, MAX_CHUNKS_PER_BUNDLE);
    }

    Ok(chunks)
}

fn gzip_size_bytes(bytes: &[u8]) -> Result<u64, ReplayBundleError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    std::io::Write::write_all(&mut encoder, bytes)?;
    let compressed = encoder.finish()?;
    Ok(u64::try_from(compressed.len()).unwrap_or(u64::MAX))
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, ReplayBundleError> {
    Ok(serde_json::to_vec(value)?)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"replay_bundle_hash_v1:" as &[u8]);
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn canonicalize_value(value: &Value, path: &str) -> Result<Value, ReplayBundleError> {
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
fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if items.len() >= cap {
        let overflow = items.len() - cap + 1;
        items.drain(0..overflow);
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
        let bundle = generate_replay_bundle("INC-RPL-001", &fixture_events()).expect("bundle");
        let outcome = replay_bundle(&bundle).expect("replay");
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
        bundle.integrity_hash = "deadbeef".repeat(8);
        let err = replay_bundle(&bundle).expect_err("must fail");
        assert!(matches!(err, ReplayBundleError::IntegrityMismatch));
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
    fn write_and_read_roundtrip() {
        let bundle = generate_replay_bundle("INC-IO-001", &fixture_events()).expect("bundle");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bundle.json");
        write_bundle_to_path(&bundle, &path).expect("write");
        let loaded = read_bundle_from_path(&path).expect("read");
        assert_eq!(bundle, loaded);
    }

    #[test]
    fn write_bundle_to_path_is_atomic_and_cleans_temp_files() {
        let first =
            generate_replay_bundle("INC-IO-ATOMIC-001", &fixture_events()).expect("first bundle");
        let second =
            generate_replay_bundle("INC-IO-ATOMIC-002", &fixture_events()).expect("second bundle");
        let dir = tempfile::tempdir().expect("tempdir");
        let dir_path = dir.path().join("nested");
        let path = dir_path.join("bundle.json");
        let temp_prefix = "bundle.json.tmp";

        write_bundle_to_path(&first, &path).expect("write first");
        let mut leftovers = temp_leftovers(&dir_path, temp_prefix);
        assert!(
            leftovers.is_empty(),
            "temporary files should not remain after first write: {leftovers:?}"
        );

        write_bundle_to_path(&second, &path).expect("write second");
        leftovers = temp_leftovers(&dir_path, temp_prefix);
        assert!(
            leftovers.is_empty(),
            "temporary files should not remain after replacement write: {leftovers:?}"
        );
    }

    #[test]
    fn read_rejects_tampered_bundle_from_disk() {
        let bundle = generate_replay_bundle("INC-IO-002", &fixture_events()).expect("bundle");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bundle.json");
        write_bundle_to_path(&bundle, &path).expect("write");

        let mut tampered: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read raw"))
                .expect("parse bundle json");
        tampered["manifest"]["event_count"] = Value::from(999_u64);
        std::fs::write(
            &path,
            serde_json::to_string(&tampered).expect("serialize tampered bundle"),
        )
        .expect("write tampered bundle");

        let err = read_bundle_from_path(&path).expect_err("must reject tampered bundle");
        assert!(matches!(err, ReplayBundleError::ManifestMismatch));
    }

    #[test]
    fn write_bundle_supports_relative_file_in_current_directory() {
        let _lock = cwd_test_lock().lock().expect("cwd test lock");
        let bundle = generate_replay_bundle("INC-IO-REL-001", &fixture_events()).expect("bundle");
        let dir = tempfile::tempdir().expect("tempdir");
        let previous_cwd = std::env::current_dir().expect("current dir");
        std::env::set_current_dir(dir.path()).expect("set cwd");

        let relative_path = Path::new("bundle.json");
        let write_result = write_bundle_to_path(&bundle, relative_path);
        let restore_result = std::env::set_current_dir(&previous_cwd);

        write_result.expect("write relative bundle");
        restore_result.expect("restore cwd");

        let loaded = read_bundle_from_path(&dir.path().join("bundle.json")).expect("read");
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
    fn evidence_package_rejects_empty_evidence_refs() {
        let mut package = fixture_evidence_package("INC-EVID-VAL-001");
        package.evidence_refs.clear();

        let err = validate_incident_evidence_package(&package, Some("INC-EVID-VAL-001"))
            .expect_err("must fail");
        assert!(matches!(err, ReplayBundleError::EvidenceRefsEmpty));
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
}
