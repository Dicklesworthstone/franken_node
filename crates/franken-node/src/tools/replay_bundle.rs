//! bd-vll: Deterministic incident replay bundle generation.
//!
//! Generates self-contained replay bundles from incident event logs and
//! replays them deterministically for outcome verification.
//!
//! Invariants:
//! - INV-RB-DETERMINISTIC: identical inputs produce byte-identical bundles
//! - INV-RB-INTEGRITY: bundle hash verifies canonical serialization
//! - INV-RB-CHUNKING: bundles larger than 10 MiB are split into indexed chunks

use std::path::Path;

use chrono::{DateTime, SecondsFormat, Utc};
use flate2::{Compression, write::GzEncoder};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const MAX_BUNDLE_BYTES: usize = 10 * 1024 * 1024;
const DEFAULT_POLICY_VERSION: &str = "0.1.0";
const DEFAULT_CREATED_AT: &str = "1970-01-01T00:00:00.000000Z";

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
    #[error("json serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bundle integrity mismatch")]
    IntegrityMismatch,
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
        original_to_new[event.original_index] = u64::try_from(new_index + 1).unwrap_or(u64::MAX);
    }

    let timeline: Vec<TimelineEvent> = prepared
        .iter()
        .enumerate()
        .map(|(index, event)| {
            let sequence_number = u64::try_from(index + 1).unwrap_or(u64::MAX);
            let mapped_parent = event.causal_parent.and_then(|p| {
                if p > 0 && (p as usize) <= event_log.len() {
                    Some(original_to_new[(p - 1) as usize])
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

    let created_at = timeline.last().map_or_else(
        || DEFAULT_CREATED_AT.to_string(),
        |event| event.timestamp.clone(),
    );

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
    let decision_sequence_hash =
        compute_decision_sequence_hash(&timeline, &initial_state_snapshot, &policy_version)?;

    let timeline_value = canonicalize_value(&serde_json::to_value(&timeline)?, "$.timeline")?;
    let timeline_bytes = canonical_json_bytes(&timeline_value)?;
    let compressed_size_bytes = gzip_size_bytes(&timeline_bytes)?;
    let chunks = chunk_timeline(bundle_id, &timeline)?;

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

    let manifest = BundleManifest {
        event_count: timeline.len(),
        first_timestamp,
        last_timestamp,
        time_span_micros,
        compressed_size_bytes,
        chunk_count: u32::try_from(chunks.len()).unwrap_or(u32::MAX),
        decision_sequence_hash,
    };

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

    let replay_timeline = if bundle.chunks.len() > 1 {
        bundle
            .chunks
            .iter()
            .flat_map(|chunk| chunk.events.iter().cloned())
            .collect::<Vec<_>>()
    } else {
        bundle.timeline.clone()
    };

    let replayed_sequence_hash = compute_decision_sequence_hash(
        &replay_timeline,
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
        event_count: replay_timeline.len(),
    })
}

pub fn write_bundle_to_path(bundle: &ReplayBundle, path: &Path) -> Result<(), ReplayBundleError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let canonical_json = to_canonical_json(bundle)?;
    std::fs::write(path, canonical_json)?;
    Ok(())
}

pub fn read_bundle_from_path(path: &Path) -> Result<ReplayBundle, ReplayBundleError> {
    let raw = std::fs::read_to_string(path)?;
    let bundle = serde_json::from_str::<ReplayBundle>(&raw)?;
    Ok(bundle)
}

pub fn to_canonical_json(bundle: &ReplayBundle) -> Result<String, ReplayBundleError> {
    let value = serde_json::to_value(bundle)?;
    let canonical = canonicalize_value(&value, "$")?;
    Ok(serde_json::to_string(&canonical)?)
}

#[must_use]
pub fn sample_incident_events(incident_id: &str) -> Vec<RawEvent> {
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
                "artifact": "sha256:incident-sample",
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

    for event in timeline {
        let event_json = canonicalize_value(&serde_json::to_value(event)?, "$.timeline_event")?;
        let event_size = canonical_json_bytes(&event_json)?.len();
        let delimiter = usize::from(!current_bucket.is_empty());

        if !current_bucket.is_empty()
            && current_size
                .saturating_add(delimiter)
                .saturating_add(event_size)
                > MAX_BUNDLE_BYTES
        {
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

#[cfg(test)]
mod tests {
    use super::*;

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

        let bundle = generate_replay_bundle("INC-CHUNK-001", &events).expect("bundle");
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
    fn write_and_read_roundtrip() {
        let bundle = generate_replay_bundle("INC-IO-001", &fixture_events()).expect("bundle");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bundle.json");
        write_bundle_to_path(&bundle, &path).expect("write");
        let loaded = read_bundle_from_path(&path).expect("read");
        assert_eq!(bundle, loaded);
    }

    #[test]
    fn sample_events_are_stable() {
        let first = sample_incident_events("INC-STABLE-001");
        let second = sample_incident_events("INC-STABLE-001");
        assert_eq!(first, second);
    }
}
