#![no_main]

use arbitrary::Arbitrary;
use ed25519_dalek::SigningKey;
use frankenengine_node::observability::evidence_ledger::{
    sign_evidence_entry, verify_evidence_entry, DecisionKind, EvidenceEntry, EvidenceLedger,
    LedgerCapacity, LedgerError,
};
use libfuzzer_sys::fuzz_target;
use serde_json::{json, Value};

const MAX_RAW_JSON_BYTES: usize = 256 * 1024;
const MAX_TEXT_CHARS: usize = 128;
const MAX_PAYLOAD_FIELDS: usize = 16;
const LEDGER_MAX_BYTES: usize = MAX_RAW_JSON_BYTES + 16 * 1024;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    raw_json: Vec<u8>,
    seed: u8,
    schema_version: String,
    entry_id: Option<String>,
    decision_id: String,
    decision_kind: u8,
    decision_time: String,
    timestamp_ms: u64,
    trace_id: String,
    epoch_id: u64,
    claimed_size_bytes: usize,
    payload_fields: Vec<(String, String)>,
    mutation_selector: u8,
}

fuzz_target!(|input: FuzzInput| {
    fuzz_raw_entry_json(&input.raw_json);
    let mut entry = structured_entry(&input);
    let signing_key = signing_key(input.seed);
    sign_evidence_entry(&mut entry, &signing_key);

    assert_signed_entry_verifies_and_appends(&entry, &signing_key);
    assert_duplicate_signed_entry_replays_fail_closed(&entry, &signing_key);
    assert_signed_field_tampering_fails_closed(&entry, &signing_key, input.mutation_selector);
    assert_json_roundtrip_is_stable(&entry);
});

fn fuzz_raw_entry_json(bytes: &[u8]) {
    if bytes.len() > MAX_RAW_JSON_BYTES {
        return;
    }

    let Ok(entry) = serde_json::from_slice::<EvidenceEntry>(bytes) else {
        return;
    };

    assert_json_roundtrip_is_stable(&entry);

    let rendered = serde_json::to_string(&entry).expect("parsed evidence entry must serialize");
    assert_eq!(entry.estimated_size(), rendered.len());

    let mut ledger = EvidenceLedger::new(LedgerCapacity::new(8, LEDGER_MAX_BYTES));
    let _ = ledger.append(entry);
}

fn assert_signed_entry_verifies_and_appends(entry: &EvidenceEntry, signing_key: &SigningKey) {
    let verifying_key = signing_key.verifying_key();
    verify_evidence_entry(entry, &verifying_key).expect("freshly signed entry must verify");

    let mut ledger =
        EvidenceLedger::with_verifying_key(LedgerCapacity::new(8, LEDGER_MAX_BYTES), verifying_key);
    let entry_id = ledger
        .append(entry.clone())
        .expect("freshly signed bounded entry must append");
    assert_eq!(entry_id.0, 1);
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger.total_appended(), 1);
}

fn assert_duplicate_signed_entry_replays_fail_closed(
    entry: &EvidenceEntry,
    signing_key: &SigningKey,
) {
    let verifying_key = signing_key.verifying_key();
    let mut ledger =
        EvidenceLedger::with_verifying_key(LedgerCapacity::new(8, LEDGER_MAX_BYTES), verifying_key);
    ledger
        .append(entry.clone())
        .expect("first signed entry append must succeed");

    let duplicate = ledger
        .append(entry.clone())
        .expect_err("duplicate timestamp+signature must fail closed as replay");
    assert!(matches!(duplicate, LedgerError::ReplayAttack { .. }));
}

fn assert_signed_field_tampering_fails_closed(
    entry: &EvidenceEntry,
    signing_key: &SigningKey,
    mutation_selector: u8,
) {
    let verifying_key = signing_key.verifying_key();
    let mut value = serde_json::to_value(entry).expect("signed entry must become JSON value");
    let object = value
        .as_object_mut()
        .expect("evidence entry JSON must be an object");

    match mutation_selector % 6 {
        0 => {
            object.insert("decision_id".to_string(), json!("tampered-decision"));
        }
        1 => {
            let replacement = if entry.decision_kind == DecisionKind::Deny {
                "release"
            } else {
                "deny"
            };
            object.insert("decision_kind".to_string(), json!(replacement));
        }
        2 => {
            object.insert(
                "payload".to_string(),
                json!({"tampered": true, "original": entry.payload}),
            );
        }
        3 => {
            object.insert(
                "timestamp_ms".to_string(),
                json!(entry.timestamp_ms.saturating_add(1)),
            );
        }
        4 => {
            object.insert("signature".to_string(), json!(""));
        }
        _ => {
            object.insert(
                "signature".to_string(),
                json!(format!("{}00", entry.signature)),
            );
        }
    }

    let encoded = serde_json::to_vec(&value).expect("tampered entry JSON must serialize");
    let Ok(tampered) = serde_json::from_slice::<EvidenceEntry>(&encoded) else {
        return;
    };
    assert!(
        verify_evidence_entry(&tampered, &verifying_key).is_err(),
        "tampered signed evidence entry must not verify"
    );
}

fn assert_json_roundtrip_is_stable(entry: &EvidenceEntry) {
    let encoded = serde_json::to_vec(entry).expect("evidence entry JSON encode");
    let decoded: EvidenceEntry =
        serde_json::from_slice(&encoded).expect("encoded evidence entry JSON decode");
    assert_eq!(&decoded, entry);

    let pretty = serde_json::to_string_pretty(entry).expect("pretty evidence entry JSON encode");
    let pretty_decoded: EvidenceEntry =
        serde_json::from_str(&pretty).expect("pretty evidence entry JSON decode");
    assert_eq!(pretty_decoded, decoded);
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
        decision_time: bounded_timestamp(&input.decision_time),
        timestamp_ms: input.timestamp_ms,
        trace_id: bounded_non_empty(&input.trace_id, "trace-fuzz"),
        epoch_id: input.epoch_id,
        payload: payload_value(input),
        size_bytes: input.claimed_size_bytes % LEDGER_MAX_BYTES,
        signature: String::new(),
        prev_entry_hash: String::new(),
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
            "source": "fuzz",
            "seed": input.seed,
            "epoch": input.epoch_id
        })
    } else {
        Value::Object(fields)
    }
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
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

fn bounded_timestamp(value: &str) -> String {
    let candidate = bounded_component(value);
    if candidate.is_empty() {
        "2026-04-23T00:00:00Z".to_string()
    } else {
        candidate
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
    value.chars().take(MAX_TEXT_CHARS).collect()
}
