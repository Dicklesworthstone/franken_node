//! Independent structural checks for the product's canonical replay format.
//!
//! This is not guest-JS re-execution. It checks that the authenticated timeline,
//! manifest and chunk representation describe the same replay. Chunk boundaries
//! use canonical JSON byte sizes, not compressed sizes. Compression is optional
//! in the producer, so gzip byte counts remain signed producer assertions.

use std::ops::Range;

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::{INCIDENT_BUNDLE_HASH_DOMAIN, IncidentBundleError, canonicalize, ct_str_eq};

// Wire-format limits from the product replay-bundle contract, not allocations
// or loop bounds supplied by the manifest of an untrusted bundle.
const MAX_EVENTS: usize = 50_000;
const MAX_CHUNKS: usize = 1_000;
const MAX_CHUNK_BYTES: usize = 10 * 1024 * 1024;
const EMPTY_CREATED_AT: &str = "1970-01-01T00:00:00.000000Z";
const EVENT_FIELDS: &[&str] = &[
    "sequence_number", "timestamp", "event_type", "payload", "causal_parent",
];
const MANIFEST_FIELDS: &[&str] = &[
    "event_count", "first_timestamp", "last_timestamp", "time_span_micros",
    "compressed_size_bytes", "chunk_count", "decision_sequence_hash",
];
const CHUNK_FIELDS: &[&str] = &[
    "bundle_id", "chunk_index", "total_chunks", "event_count",
    "first_sequence_number", "last_sequence_number", "compressed_size_bytes",
    "chunk_hash", "events",
];

type Result<T> = std::result::Result<T, IncidentBundleError>;

fn invalid(path: impl Into<String>, reason: &'static str) -> IncidentBundleError {
    IncidentBundleError::Structure { path: path.into(), reason }
}

fn member<'a>(object: &'a Map<String, Value>, key: &str, path: &str) -> Result<&'a Value> {
    object.get(key).ok_or_else(|| invalid(format!("{path}.{key}"), "missing field"))
}

fn text<'a>(object: &'a Map<String, Value>, key: &str, path: &str) -> Result<&'a str> {
    member(object, key, path)?.as_str()
        .ok_or_else(|| invalid(format!("{path}.{key}"), "expected string"))
}

fn uint(object: &Map<String, Value>, key: &str, path: &str) -> Result<u64> {
    member(object, key, path)?.as_u64()
        .ok_or_else(|| invalid(format!("{path}.{key}"), "expected unsigned integer"))
}

fn expect_uint(object: &Map<String, Value>, key: &str, path: &str, expected: u64) -> Result<()> {
    if uint(object, key, path)? != expected {
        return Err(invalid(format!("{path}.{key}"), "does not match replay derivation"));
    }
    Ok(())
}

fn exact_object<'a>(value: &'a Value, path: &str, fields: &[&str]) -> Result<&'a Map<String, Value>> {
    let object = value.as_object().ok_or_else(|| invalid(path, "expected object"))?;
    for field in fields {
        member(object, field, path)?;
    }
    if object.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err(invalid(path, "unknown field in canonical replay structure"));
    }
    Ok(object)
}

fn array<'a>(value: &'a Value, path: &str) -> Result<&'a [Value]> {
    value.as_array().map(Vec::as_slice).ok_or_else(|| invalid(path, "expected array"))
}

fn canonical_bytes(value: &Value, path: &str) -> Result<Vec<u8>> {
    serde_json::to_vec(&canonicalize(value, path)?)
        .map_err(|error| IncidentBundleError::Json(error.to_string()))
}

fn timestamp_micros(timestamp: &str, path: &str) -> Result<i64> {
    let parsed = DateTime::parse_from_rfc3339(timestamp)
        .map_err(|_| invalid(path, "invalid RFC3339 timestamp"))?;
    if parsed.with_timezone(&Utc).to_rfc3339_opts(SecondsFormat::Micros, true) != timestamp {
        return Err(invalid(path, "expected canonical UTC microsecond timestamp"));
    }
    Ok(parsed.timestamp_micros())
}

fn verify_timeline(timeline: &[Value]) -> Result<u64> {
    if timeline.len() > MAX_EVENTS {
        return Err(invalid("$.timeline", "event count exceeds replay limit"));
    }
    let mut first_micros = None;
    let mut previous_micros = None;
    for (index, value) in timeline.iter().enumerate() {
        let path = format!("$.timeline[{index}]");
        let event = exact_object(value, &path, EVENT_FIELDS)?;
        let sequence = index as u64 + 1;
        expect_uint(event, "sequence_number", &path, sequence)?;
        let micros = timestamp_micros(text(event, "timestamp", &path)?, &format!("{path}.timestamp"))?;
        if previous_micros.is_some_and(|previous| micros < previous) {
            return Err(invalid(format!("{path}.timestamp"), "timeline timestamps decrease"));
        }
        first_micros.get_or_insert(micros);
        previous_micros = Some(micros);
        match text(event, "event_type", &path)? {
            "state_change" | "policy_eval" | "external_signal" | "operator_action" => {}
            _ => return Err(invalid(format!("{path}.event_type"), "unknown replay event type")),
        }
        let parent = member(event, "causal_parent", &path)?;
        if !parent.is_null() && !parent.as_u64().is_some_and(|parent| parent > 0 && parent < sequence) {
            return Err(invalid(format!("{path}.causal_parent"), "parent must name an earlier event"));
        }
    }
    // Match the producer's saturating microsecond span at the chrono range edge.
    Ok(match (first_micros, previous_micros) {
        (Some(first), Some(last)) => last.saturating_sub(first) as u64,
        _ => 0,
    })
}

#[derive(Debug, PartialEq, Eq)]
struct ExpectedChunk {
    events: Range<usize>,
    hash: String,
}

fn chunk_hasher() -> Sha256 {
    let mut hash = Sha256::new();
    hash.update(INCIDENT_BUNDLE_HASH_DOMAIN);
    hash.update(b"[");
    hash
}

fn finish_chunk(mut hash: Sha256, events: Range<usize>) -> ExpectedChunk {
    hash.update(b"]");
    ExpectedChunk { events, hash: hex::encode(hash.finalize()) }
}

/// Stream one event's canonical bytes at a time. Reconstructing chunk digests
/// never clones the whole timeline or trusts recorded counts/offsets for slicing.
fn expected_chunks(timeline: &[Value], max_bytes: usize) -> Result<Vec<ExpectedChunk>> {
    let mut chunks = Vec::new();
    let mut start = 0;
    let mut size = 2; // array brackets
    let mut hash = chunk_hasher();
    for (index, event) in timeline.iter().enumerate() {
        let bytes = canonical_bytes(event, &format!("$.timeline[{index}]"))?;
        if bytes.len() >= max_bytes.saturating_sub(2) {
            return Err(invalid(format!("$.timeline[{index}]"), "event exceeds chunk byte limit"));
        }
        if index > start && size + 1 + bytes.len() > max_bytes {
            chunks.push(finish_chunk(hash, start..index));
            if chunks.len() >= MAX_CHUNKS {
                return Err(invalid("$.chunks", "chunk count exceeds replay limit"));
            }
            hash = chunk_hasher();
            start = index;
            size = 2;
        }
        if index > start {
            hash.update(b",");
            size += 1;
        }
        hash.update(&bytes);
        size += bytes.len();
    }
    // The product represents an empty timeline with one zero-event chunk.
    chunks.push(finish_chunk(hash, start..timeline.len()));
    Ok(chunks)
}

fn expected_bundle_id(incident_id: &str, created_at: &str, timeline: &[Value]) -> Result<String> {
    let seed = serde_json::json!({
        "incident_id": incident_id,
        "created_at": created_at,
        "timeline": timeline,
    });
    let mut hash = Sha256::new();
    hash.update(b"replay_bundle_seed_v1:");
    hash.update(canonical_bytes(&seed, "$.bundle_seed")?);
    let entropy = hash.finalize();
    let millis = DateTime::parse_from_rfc3339(created_at)
        .map_err(|_| invalid("$.created_at", "invalid RFC3339 timestamp"))?
        .timestamp_millis().max(0) as u64;
    let time = millis.to_be_bytes();
    let mut bytes = [0_u8; 16];
    bytes[..6].copy_from_slice(&time[2..]);
    bytes[6] = 0x70 | (entropy[0] & 0x0f);
    bytes[7] = entropy[1];
    bytes[8] = 0x80 | (entropy[2] & 0x3f);
    bytes[9..].copy_from_slice(&entropy[3..10]);
    let hex = hex::encode(bytes);
    Ok(format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..]))
}

pub(super) fn verify_structure(bundle: &Map<String, Value>) -> Result<()> {
    let timeline = array(member(bundle, "timeline", "$")?, "$.timeline")?;
    let span = verify_timeline(timeline)?;
    let incident_id = text(bundle, "incident_id", "$")?;
    if incident_id.trim().is_empty() || incident_id.trim() != incident_id
        || incident_id.chars().any(char::is_control)
        || incident_id.contains('/') || incident_id.contains('\\') || incident_id.contains("..")
    {
        return Err(invalid("$.incident_id", "invalid incident identifier"));
    }
    if text(bundle, "policy_version", "$")?.trim().is_empty() {
        return Err(invalid("$.policy_version", "empty policy version"));
    }
    let created_at = text(bundle, "created_at", "$")?;
    let expected_created = timeline.last()
        .and_then(|event| event["timestamp"].as_str()).unwrap_or(EMPTY_CREATED_AT);
    if created_at != expected_created {
        return Err(invalid("$.created_at", "does not match final timeline timestamp"));
    }
    let bundle_id = text(bundle, "bundle_id", "$")?;
    if !ct_str_eq(bundle_id, &expected_bundle_id(incident_id, created_at, timeline)?) {
        return Err(invalid("$.bundle_id", "does not match deterministic replay identity"));
    }

    let manifest = exact_object(member(bundle, "manifest", "$")?, "$.manifest", MANIFEST_FIELDS)?;
    expect_uint(manifest, "event_count", "$.manifest", timeline.len() as u64)?;
    expect_uint(manifest, "time_span_micros", "$.manifest", span)?;
    for (field, event) in [("first_timestamp", timeline.first()), ("last_timestamp", timeline.last())] {
        let recorded = member(manifest, field, "$.manifest")?;
        let matches = match event {
            Some(event) => recorded == &event["timestamp"],
            None => recorded.is_null(),
        };
        if !matches {
            return Err(invalid(format!("$.manifest.{field}"), "does not match timeline endpoint"));
        }
    }
    uint(manifest, "compressed_size_bytes", "$.manifest")?;
    let chunks = array(member(bundle, "chunks", "$")?, "$.chunks")?;
    if chunks.is_empty() || chunks.len() > MAX_CHUNKS {
        return Err(invalid("$.chunks", "invalid number of replay chunks"));
    }
    let expected = expected_chunks(timeline, MAX_CHUNK_BYTES)?;
    if chunks.len() != expected.len() {
        return Err(invalid("$.chunks", "does not match canonical byte-size partition"));
    }
    expect_uint(manifest, "chunk_count", "$.manifest", expected.len() as u64)?;
    for (index, (value, expected)) in chunks.iter().zip(&expected).enumerate() {
        let path = format!("$.chunks[{index}]");
        let chunk = exact_object(value, &path, CHUNK_FIELDS)?;
        if text(chunk, "bundle_id", &path)? != bundle_id {
            return Err(invalid(format!("{path}.bundle_id"), "chunk belongs to a different bundle"));
        }
        expect_uint(chunk, "chunk_index", &path, index as u64)?;
        expect_uint(chunk, "total_chunks", &path, chunks.len() as u64)?;
        expect_uint(chunk, "event_count", &path, expected.events.len() as u64)?;
        let first = if expected.events.is_empty() { 0 } else { expected.events.start as u64 + 1 };
        expect_uint(chunk, "first_sequence_number", &path, first)?;
        expect_uint(chunk, "last_sequence_number", &path, expected.events.end as u64)?;
        let events = array(member(chunk, "events", &path)?, &format!("{path}.events"))?;
        if events != &timeline[expected.events.clone()] {
            return Err(invalid(format!("{path}.events"), "chunk events differ from timeline partition"));
        }
        if !ct_str_eq(text(chunk, "chunk_hash", &path)?, &expected.hash) {
            return Err(invalid(format!("{path}.chunk_hash"), "does not match canonical event digest"));
        }
        let compressed_size = uint(chunk, "compressed_size_bytes", &path)?;
        if expected.events.is_empty() && compressed_size != 0 {
            return Err(invalid(format!("{path}.compressed_size_bytes"), "empty chunk must have zero size"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    use crate::incident_bundle::{
        incident_bundle_canonical_digest, incident_bundle_signature_payload,
        verify_incident_bundle,
    };

    const FIXTURE: &[u8] =
        include_bytes!("../tests/fixtures/cli_incident_bundle/INC-SDK-FIXTURE-1.fnbundle");

    fn fixture() -> Value {
        serde_json::from_slice(FIXTURE).unwrap()
    }

    fn fixture_key() -> SigningKey {
        // Published RFC 8032 TEST 1 fixture key, never a production trust key.
        let mut seed = [0_u8; 32];
        hex::decode_to_slice(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            &mut seed,
        ).unwrap();
        SigningKey::from_bytes(&seed)
    }

    /// Sign even inconsistent structures, so rejection cannot be credited to a
    /// stale outer digest, decision-sequence hash, or invalid Ed25519 signature.
    fn resign(bundle: &mut Value) -> Vec<u8> {
        let sequence = serde_json::json!({
            "timeline": bundle["timeline"],
            "initial_state_snapshot": bundle["initial_state_snapshot"],
            "policy_version": bundle["policy_version"],
        });
        bundle["manifest"]["decision_sequence_hash"] =
            incident_bundle_canonical_digest(&sequence, "$").unwrap().into();
        let mut view = bundle.as_object().unwrap().clone();
        view.remove("signature");
        view.remove("integrity_hash");
        let integrity = incident_bundle_canonical_digest(&Value::Object(view), "$").unwrap();
        let payload = incident_bundle_signature_payload(&integrity);
        bundle["integrity_hash"] = integrity.into();
        let key = fixture_key();
        let signature = key.sign(&payload);
        key.verifying_key().verify_strict(&payload, &signature).unwrap();
        bundle["signature"]["signed_payload_sha256"] = hex::encode(Sha256::digest(&payload)).into();
        bundle["signature"]["signature_hex"] = hex::encode(signature.to_bytes()).into();
        serde_json::to_vec(bundle).unwrap()
    }

    fn assert_structure_rejected(mut bundle: Value, expected_path: &str) {
        let bytes = resign(&mut bundle);
        let error = verify_incident_bundle(&bytes, &fixture_key().verifying_key()).unwrap_err();
        match error {
            IncidentBundleError::Structure { path, .. } => assert_eq!(path, expected_path),
            other => panic!("expected structural rejection at {expected_path}, got {other}"),
        }
    }

    /// Build explicit caller-selected partitions for conformance tests. Unlike
    /// the verifier, this helper does NOT choose or validate chunk boundaries.
    fn set_chunks(bundle: &mut Value, ranges: &[Range<usize>]) {
        let timeline = bundle["timeline"].as_array().unwrap();
        let chunks: Vec<Value> = ranges.iter().enumerate().map(|(index, range)| {
            let events = Value::Array(timeline[range.clone()].to_vec());
            let size = if range.is_empty() { 0 } else { canonical_bytes(&events, "$").unwrap().len() };
            serde_json::json!({
                "bundle_id": bundle["bundle_id"],
                "chunk_index": index,
                "total_chunks": ranges.len(),
                "event_count": range.len(),
                "first_sequence_number": if range.is_empty() { 0 } else { range.start + 1 },
                "last_sequence_number": range.end,
                // Matches the producer built without its optional compression feature.
                "compressed_size_bytes": size,
                "chunk_hash": incident_bundle_canonical_digest(&events, "$").unwrap(),
                "events": events,
            })
        }).collect();
        bundle["chunks"] = chunks.into();
        bundle["manifest"]["chunk_count"] = Value::from(ranges.len());
    }

    fn refresh_timeline_metadata(bundle: &mut Value) {
        let timeline = bundle["timeline"].as_array().unwrap();
        let created = timeline.last().map_or(EMPTY_CREATED_AT, |event| event["timestamp"].as_str().unwrap());
        let id = expected_bundle_id(bundle["incident_id"].as_str().unwrap(), created, timeline).unwrap();
        let first = timeline.first().map_or(Value::Null, |event| event["timestamp"].clone());
        let last = timeline.last().map_or(Value::Null, |event| event["timestamp"].clone());
        let span = verify_timeline(timeline).unwrap();
        let count = timeline.len();
        let size = canonical_bytes(&bundle["timeline"], "$").unwrap().len();
        let created = created.to_string();
        bundle["bundle_id"] = id.into();
        bundle["created_at"] = created.into();
        bundle["manifest"]["event_count"] = count.into();
        bundle["manifest"]["first_timestamp"] = first;
        bundle["manifest"]["last_timestamp"] = last;
        bundle["manifest"]["time_span_micros"] = span.into();
        bundle["manifest"]["compressed_size_bytes"] = size.into();
    }

    #[test]
    fn real_producer_fixture_has_the_independently_derived_structure() {
        let bundle = fixture();
        verify_structure(bundle.as_object().unwrap()).unwrap();
        assert_eq!(expected_bundle_id(
            "INC-SDK-FIXTURE-1", "2026-02-20T10:00:00.000300Z",
            bundle["timeline"].as_array().unwrap(),
        ).unwrap(), "019c7a7d-f100-7213-b85f-5f6d5f1eda0a");
        let chunks = expected_chunks(bundle["timeline"].as_array().unwrap(), MAX_CHUNK_BYTES).unwrap();
        assert_eq!(chunks[0].hash, "16ca84c76463b7ad73d12656da12230a3c4d594000204dbc0f36a8dcdd00ca9d");
    }

    #[test]
    fn valid_signature_does_not_authenticate_invented_chunk_metadata() {
        for (pointer, value) in [
            ("/chunks/0/chunk_index", Value::from(1)),
            ("/chunks/0/total_chunks", Value::from(2)),
            ("/chunks/0/event_count", Value::from(u64::MAX)),
            ("/chunks/0/first_sequence_number", Value::from(0)),
            ("/chunks/0/last_sequence_number", Value::from(2)),
            ("/chunks/0/bundle_id", Value::from("another-bundle")),
            ("/chunks/0/chunk_hash", Value::from("0".repeat(64))),
            ("/chunks/0/compressed_size_bytes", Value::from(-1)),
        ] {
            let mut bundle = fixture();
            *bundle.pointer_mut(pointer).unwrap() = value;
            let field = pointer.rsplit('/').next().unwrap();
            assert_structure_rejected(bundle, &format!("$.chunks[0].{field}"));
        }
    }

    #[test]
    fn rehashed_chunk_payload_must_still_match_the_timeline() {
        let mut bundle = fixture();
        bundle["chunks"][0]["events"][1]["payload"]["decision"] = "release".into();
        bundle["chunks"][0]["chunk_hash"] =
            incident_bundle_canonical_digest(&bundle["chunks"][0]["events"], "$").unwrap().into();
        assert_structure_rejected(bundle, "$.chunks[0].events");
    }

    #[test]
    fn missing_duplicate_or_reordered_chunk_events_are_rejected() {
        for mode in 0..3 {
            let mut bundle = fixture();
            let events = bundle["chunks"][0]["events"].as_array_mut().unwrap();
            match mode {
                0 => { events.pop(); }
                1 => { events.push(events[0].clone()); }
                _ => events.swap(0, 1),
            }
            assert_structure_rejected(bundle, "$.chunks[0].events");
        }
    }

    #[test]
    fn hash_valid_noncanonical_partition_is_rejected() {
        let mut bundle = fixture();
        // All chunk hashes, offsets and counts are internally consistent, but
        // splitting three tiny events violates the actual 10 MiB partition.
        set_chunks(&mut bundle, &[0..1, 1..3]);
        assert_structure_rejected(bundle, "$.chunks");
    }

    #[test]
    fn missing_and_unbounded_chunk_arrays_fail_closed() {
        let mut absent = fixture();
        absent["chunks"] = serde_json::json!([]);
        assert_structure_rejected(absent, "$.chunks");
        let mut oversized = fixture();
        let chunk = oversized["chunks"][0].clone();
        oversized["chunks"] = vec![chunk; MAX_CHUNKS + 1].into();
        assert_structure_rejected(oversized, "$.chunks");
    }

    #[test]
    fn manifest_endpoints_counts_and_span_are_recomputed() {
        for (field, value) in [
            ("first_timestamp", Value::Null),
            ("last_timestamp", Value::from("2026-02-20T10:00:00.000100Z")),
            ("time_span_micros", Value::from(201)),
            ("chunk_count", Value::from(2)),
            ("compressed_size_bytes", Value::from("488")),
        ] {
            let mut bundle = fixture();
            bundle["manifest"][field] = value;
            assert_structure_rejected(bundle, &format!("$.manifest.{field}"));
        }
    }

    #[test]
    fn valid_signature_cannot_relabel_bundle_identity_or_creation_time() {
        let mut identity = fixture();
        identity["incident_id"] = "INC-ANOTHER".into();
        assert_structure_rejected(identity, "$.bundle_id");
        let mut uuid = fixture();
        uuid["bundle_id"] = "00000000-0000-7000-8000-000000000000".into();
        assert_structure_rejected(uuid, "$.bundle_id");
        let mut time = fixture();
        time["created_at"] = "2026-02-20T10:00:00.000301Z".into();
        assert_structure_rejected(time, "$.created_at");
    }

    #[test]
    fn timeline_sequence_gaps_duplicates_and_integer_overflow_are_rejected() {
        for number in [Value::from(0), Value::from(1), Value::from(u64::MAX), Value::from(-1)] {
            let mut bundle = fixture();
            bundle["timeline"][1]["sequence_number"] = number;
            assert_structure_rejected(bundle, "$.timeline[1].sequence_number");
        }
    }

    #[test]
    fn causal_parents_must_be_existing_earlier_events() {
        for parent in [Value::from(0), Value::from(2), Value::from(3), Value::from("1")] {
            let mut bundle = fixture();
            bundle["timeline"][1]["causal_parent"] = parent;
            assert_structure_rejected(bundle, "$.timeline[1].causal_parent");
        }
    }

    #[test]
    fn decreasing_invalid_or_noncanonical_timestamps_are_rejected() {
        for timestamp in [
            "2026-02-20T10:00:00.000099Z",
            "not-a-timestamp",
            "2026-02-20T10:00:00.000200+00:00",
            "2026-02-20T10:00:00.000200001Z",
        ] {
            let mut bundle = fixture();
            bundle["timeline"][1]["timestamp"] = timestamp.into();
            assert_structure_rejected(bundle, "$.timeline[1].timestamp");
        }
    }

    #[test]
    fn canonical_nested_schema_cannot_carry_unknown_or_missing_fields() {
        for (pointer, path) in [
            ("/timeline/0", "$.timeline[0]"),
            ("/chunks/0", "$.chunks[0]"),
            ("/manifest", "$.manifest"),
        ] {
            let mut bundle = fixture();
            bundle.pointer_mut(pointer).unwrap()["hidden"] = true.into();
            assert_structure_rejected(bundle, path);
        }
        let mut missing = fixture();
        missing["timeline"][0].as_object_mut().unwrap().remove("payload");
        assert_structure_rejected(missing, "$.timeline[0].payload");
        let mut unknown_type = fixture();
        unknown_type["timeline"][0]["event_type"] = "made-up-event".into();
        assert_structure_rejected(unknown_type, "$.timeline[0].event_type");
    }

    #[test]
    fn timeline_limit_is_checked_before_event_traversal() {
        let timeline = vec![Value::Null; MAX_EVENTS + 1];
        assert!(matches!(verify_timeline(&timeline),
            Err(IncidentBundleError::Structure { path, .. }) if path == "$.timeline"));
    }

    #[test]
    fn canonical_partition_uses_utf8_bytes_and_exact_delimiters() {
        let events = vec![serde_json::json!({"text":"é"}); 3];
        let event_len = canonical_bytes(&events[0], "$").unwrap().len();
        let exactly_two = event_len * 2 + 3; // brackets plus one comma
        let chunks = expected_chunks(&events, exactly_two).unwrap();
        assert_eq!(chunks.iter().map(|chunk| chunk.events.clone()).collect::<Vec<_>>(), vec![0..2, 2..3]);
        let smaller = expected_chunks(&events, exactly_two - 1).unwrap();
        assert_eq!(smaller.iter().map(|chunk| chunk.events.clone()).collect::<Vec<_>>(), vec![0..1, 1..2, 2..3]);
        for chunk in chunks {
            let value = Value::Array(events[chunk.events].to_vec());
            assert_eq!(chunk.hash, incident_bundle_canonical_digest(&value, "$").unwrap());
        }
    }

    #[test]
    fn oversized_single_event_is_not_hidden_by_compression_claims() {
        // The producer rejects event JSON >= MAX_CHUNK_BYTES - 2, even if an
        // attacker supplies a tiny compressed_size_bytes in the signed envelope.
        assert!(expected_chunks(&[Value::from("xxxxxx")], 10).is_err());
        assert!(expected_chunks(&[Value::from("xxxxx")], 10).is_ok());
    }

    #[test]
    fn empty_replay_requires_the_canonical_single_empty_chunk() {
        let mut bundle = fixture();
        bundle["timeline"] = serde_json::json!([]);
        refresh_timeline_metadata(&mut bundle);
        set_chunks(&mut bundle, &[0..0]);
        let bytes = resign(&mut bundle);
        let verified = verify_incident_bundle(&bytes, &fixture_key().verifying_key()).unwrap();
        assert_eq!(verified.event_count, 0);
        assert_eq!(verified.created_at, EMPTY_CREATED_AT);
        let mut bad_size = bundle.clone();
        bad_size["chunks"][0]["compressed_size_bytes"] = 1.into();
        assert_structure_rejected(bad_size, "$.chunks[0].compressed_size_bytes");
        bundle["chunks"] = serde_json::json!([]);
        assert_structure_rejected(bundle, "$.chunks");
    }

    #[test]
    fn authentic_multichunk_replay_crosses_real_ten_mebibyte_boundary() {
        let mut bundle = fixture();
        for event in bundle["timeline"].as_array_mut().unwrap() {
            event["payload"] = Value::from("x".repeat(4 * 1024 * 1024));
        }
        refresh_timeline_metadata(&mut bundle);
        // Two ~4 MiB events fit, but three do not. Choose this independently
        // rather than invoking the partition function being tested.
        set_chunks(&mut bundle, &[0..2, 2..3]);
        let bytes = resign(&mut bundle);
        assert!(verify_incident_bundle(&bytes, &fixture_key().verifying_key()).is_ok());
        bundle["chunks"].as_array_mut().unwrap().swap(0, 1);
        assert_structure_rejected(bundle, "$.chunks[0].chunk_index");
    }
}
