#![no_main]
#![forbid(unsafe_code)]

use arbitrary::Arbitrary;
use frankenengine_node::observability::evidence_ledger::{DecisionKind, EvidenceEntry};
use libfuzzer_sys::fuzz_target;
use serde_json::{json, Value};
use std::str;

const MAX_JSONL_BYTES: usize = 128 * 1024;
const MAX_TEXT_CHARS: usize = 128;
const MAX_PAYLOAD_FIELDS: usize = 16;

fuzz_target!(|input: FuzzInput| {
    fuzz_raw_jsonl(&input.raw_jsonl);
    let entry = structured_entry(&input);
    assert_jsonl_round_trip(&entry);
});

fn fuzz_raw_jsonl(bytes: &[u8]) {
    if bytes.len() > MAX_JSONL_BYTES {
        return;
    }

    let Ok(jsonl) = str::from_utf8(bytes) else {
        return;
    };

    for line in jsonl.lines().filter(|line| !line.trim().is_empty()) {
        let Ok(entry) = serde_json::from_str::<EvidenceEntry>(line) else {
            continue;
        };
        assert_jsonl_round_trip(&entry);
    }
}

fn assert_jsonl_round_trip(entry: &EvidenceEntry) {
    let encoded = serde_json::to_string(entry).expect("EvidenceEntry JSONL encode must not fail");
    assert!(
        !encoded.contains('\n'),
        "compact EvidenceEntry JSONL encoding must stay single-line"
    );

    let decoded: EvidenceEntry =
        serde_json::from_str(&encoded).expect("serializer-produced EvidenceEntry must parse");
    assert_eq!(&decoded, entry, "parse(write(entry)) must preserve entry");

    let encoded_again =
        serde_json::to_string(&decoded).expect("round-tripped EvidenceEntry must re-encode");
    assert_eq!(
        encoded, encoded_again,
        "EvidenceEntry JSONL encoding must be stable after parse"
    );

    let with_newline = format!("{encoded}\n");
    let parsed_line: EvidenceEntry = with_newline
        .lines()
        .next()
        .and_then(|line| serde_json::from_str(line).ok())
        .expect("JSONL line parser must accept serializer output");
    assert_eq!(parsed_line, decoded);

    let estimated_size = decoded.estimated_size();
    assert!(
        estimated_size >= encoded.len(),
        "estimated size must not undercount compact JSONL encoding"
    );
}

fn structured_entry(input: &FuzzInput) -> EvidenceEntry {
    EvidenceEntry {
        schema_version: bounded_non_empty(&input.schema_version, "evidence-ledger-v1"),
        entry_id: input
            .entry_id
            .as_deref()
            .map(|value| bounded_non_empty(value, "entry-fuzz")),
        decision_id: bounded_non_empty(&input.decision_id, "decision-fuzz"),
        decision_kind: decision_kind(input.decision_kind),
        decision_time: bounded_non_empty(&input.decision_time, "2026-04-30T00:00:00Z"),
        timestamp_ms: input.timestamp_ms,
        trace_id: bounded_non_empty(&input.trace_id, "trace-fuzz"),
        epoch_id: input.epoch_id,
        payload: payload_value(input),
        size_bytes: input.size_bytes % MAX_JSONL_BYTES,
        signature: bounded_component(&input.signature),
        prev_entry_hash: bounded_component(&input.prev_entry_hash),
    }
}

fn payload_value(input: &FuzzInput) -> Value {
    let fields = input
        .payload_fields
        .iter()
        .take(MAX_PAYLOAD_FIELDS)
        .enumerate()
        .map(|(index, (key, value))| {
            (
                bounded_non_empty(key, &format!("field-{index}")),
                json!(bounded_component(value)),
            )
        })
        .collect::<serde_json::Map<String, Value>>();

    if fields.is_empty() {
        json!({
            "source": "jsonl-spill-fuzz",
            "epoch": input.epoch_id,
            "selector": input.decision_kind
        })
    } else {
        Value::Object(fields)
    }
}

fn decision_kind(value: u8) -> DecisionKind {
    match value % 7 {
        0 => DecisionKind::Admit,
        1 => DecisionKind::Deny,
        2 => DecisionKind::Quarantine,
        3 => DecisionKind::Release,
        4 => DecisionKind::Rollback,
        5 => DecisionKind::Throttle,
        _ => DecisionKind::Escalate,
    }
}

fn bounded_non_empty(value: &str, fallback: &str) -> String {
    let bounded = bounded_component(value);
    if bounded.is_empty() {
        fallback.to_string()
    } else {
        bounded
    }
}

fn bounded_component(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_TEXT_CHARS)
        .collect()
}

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    raw_jsonl: Vec<u8>,
    schema_version: String,
    entry_id: Option<String>,
    decision_id: String,
    decision_kind: u8,
    decision_time: String,
    timestamp_ms: u64,
    trace_id: String,
    epoch_id: u64,
    payload_fields: Vec<(String, String)>,
    size_bytes: usize,
    signature: String,
    prev_entry_hash: String,
}
