//! Integration tests for bd-1hj3 / bd-1hj3.1 — local ATC signal extraction.
//!
//! Exercises the *public* surface of
//! `frankenengine_node::federation::atc_signal_extractor`. The matching
//! in-source `#[cfg(test)] mod tests` block in `atc_signal_extractor.rs`
//! covers private-field invariants; this file covers the contract-level
//! behavior gated by the bead's acceptance criteria:
//!
//! - Extraction is deterministic for identical inputs.
//! - Sensitive raw payloads are excluded by policy.
//! - Extraction outputs are replay-auditable (signal_id reproducible from
//!   the raw event's trace_id, kind, and source_epoch).
//!
//! The integration test also walks the 5-trace JSONL fixture under
//! `tests/fixtures/atc_signal_samples.jsonl` end-to-end.
//!
//! The `federation` module is gated behind the `advanced-features` feature
//! flag in `crates/franken-node/src/lib.rs`, so this entire test file is
//! cfg-gated to match.

#![cfg(feature = "advanced-features")]

use frankenengine_node::federation::atc_signal_extractor::{
    AtcLocalSignal, ExtractionAuditLog, ExtractionError, ExtractionPolicy, SignalKind, event_codes,
    extract_signal,
};
use proptest::prelude::*;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn permissive_policy() -> ExtractionPolicy {
    ExtractionPolicy::permissive_for_tests()
}

fn redacting_policy() -> ExtractionPolicy {
    let mut p = permissive_policy();
    p.redact_fields.push("secret_token".to_string());
    p
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/atc_signal_samples.jsonl")
}

fn sample_event(kind: &str, trace: &str, epoch: u64) -> serde_json::Value {
    json!({
        "event_type": kind,
        "trace_id": trace,
        "source_epoch": epoch,
        "contributor_pubkey_hex": "deadbeef",
        "payload": {
            "host": "node-1",
            "score": 0.91,
            "secret_token": "REDACT-ME",
        }
    })
}

fn fuzz_signal_kind(tag: u8) -> SignalKind {
    match tag % 4 {
        0 => SignalKind::AnomalyObservation,
        1 => SignalKind::TrustCardDelta,
        2 => SignalKind::RevocationHint,
        _ => SignalKind::QuarantineEvent,
    }
}

fn field_name_strategy() -> BoxedStrategy<String> {
    proptest::string::string_regex("[a-z][a-z0-9_]{0,15}")
        .expect("field-name regex is valid")
        .boxed()
}

fn scalar_value_strategy() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        (-1_000_000_i64..=1_000_000_i64).prop_map(|n| json!(n)),
        "[A-Za-z0-9_:@./ -]{0,48}".prop_map(Value::String),
    ]
}

fn policy_allowing(kind: SignalKind, redact_fields: Vec<String>) -> ExtractionPolicy {
    let mut allowed_kinds = BTreeSet::new();
    allowed_kinds.insert(kind);
    ExtractionPolicy {
        redact_fields,
        max_payload_bytes: 4096,
        allowed_kinds,
    }
}

fn event_from_payload(
    kind: SignalKind,
    trace_id: &str,
    source_epoch: u64,
    contributor_pubkey_hex: &str,
    payload: &BTreeMap<String, Value>,
    reverse_payload_order: bool,
) -> Value {
    let mut payload_entries: Vec<_> = payload.iter().collect();
    if reverse_payload_order {
        payload_entries.reverse();
    }
    let mut payload_obj = Map::new();
    for (field, value) in payload_entries {
        payload_obj.insert(field.clone(), value.clone());
    }

    json!({
        "event_type": kind.as_str(),
        "trace_id": trace_id,
        "source_epoch": source_epoch,
        "contributor_pubkey_hex": contributor_pubkey_hex,
        "payload": Value::Object(payload_obj),
    })
}

fn scalar_to_string(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some("null".to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::String(value) => Some(value.clone()),
        Value::Array(_) | Value::Object(_) => None,
    }
}

fn expected_redacted_payload(
    payload: &BTreeMap<String, Value>,
    redact_fields: &[String],
) -> BTreeMap<String, String> {
    let redact: BTreeSet<&str> = redact_fields.iter().map(String::as_str).collect();
    payload
        .iter()
        .filter(|(field, _)| !redact.contains(field.as_str()))
        .filter_map(|(field, value)| scalar_to_string(value).map(|value| (field.clone(), value)))
        .collect()
}

// ---------------------------------------------------------------------------
// Public-surface contract tests (mirror bead acceptance criteria)
// ---------------------------------------------------------------------------

#[test]
fn public_extract_is_deterministic_for_identical_inputs() {
    let policy = redacting_policy();
    let ev = sample_event("anomaly_observation", "trace-pub-001", 42);
    let a = extract_signal(&ev, &policy).expect("a");
    let b = extract_signal(&ev, &policy).expect("b");
    assert_eq!(a, b, "INV-ATC-EXTRACT-DETERMINISM violated");
}

#[test]
fn public_extract_redacts_sensitive_fields_by_policy() {
    let strict = redacting_policy();
    let sig = extract_signal(
        &sample_event("trust_card_delta", "trace-pub-002", 7),
        &strict,
    )
    .expect("extract");
    assert!(
        !sig.redacted_payload.contains_key("secret_token"),
        "INV-ATC-EXTRACT-REDACTION violated: secret_token leaked"
    );
    // Non-redacted fields survive.
    assert!(sig.redacted_payload.contains_key("host"));
}

#[test]
fn public_extract_output_is_replay_auditable() {
    // Two independent extractions of identical raw bytes produce identical
    // signal_id and payload_hash. The trace_id is echoed unchanged so an
    // auditor can re-derive both deterministic IDs from the source bytes.
    let policy = redacting_policy();
    let raw = sample_event(
        "revocation_hint",
        "trace-pub-003-replay-audit-correlation-id",
        99,
    );
    let a = extract_signal(&raw, &policy).unwrap();
    let b = extract_signal(&raw, &policy).unwrap();
    assert_eq!(a.signal_id, b.signal_id);
    assert_eq!(a.payload_hash, b.payload_hash);
    assert_eq!(a.trace_id, "trace-pub-003-replay-audit-correlation-id");
}

#[test]
fn public_extract_rejects_kind_outside_policy_allow_list() {
    let mut policy = permissive_policy();
    policy.allowed_kinds.remove(&SignalKind::QuarantineEvent);
    let err = extract_signal(
        &sample_event("quarantine_event", "trace-pub-004", 1),
        &policy,
    )
    .expect_err("must reject");
    assert!(
        matches!(err, ExtractionError::KindFiltered { .. }),
        "expected KindFiltered, got {err:?}"
    );
    assert_eq!(err.code(), event_codes::KIND_FILTERED);
}

#[test]
fn public_extract_enforces_max_payload_bytes_fail_closed() {
    let mut policy = permissive_policy();
    policy.max_payload_bytes = 0; // fail-closed at boundary
    let err = extract_signal(
        &sample_event("anomaly_observation", "trace-pub-005", 1),
        &policy,
    )
    .expect_err("must reject");
    assert!(matches!(err, ExtractionError::PayloadTooLarge { .. }));
    assert_eq!(err.code(), event_codes::PAYLOAD_TOO_LARGE);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn fuzz_structured_signal_events_are_canonical_and_private(
        kind_tag in any::<u8>(),
        trace_id in "[A-Za-z0-9_:@./-]{1,64}",
        source_epoch in any::<u64>(),
        contributor_pubkey_hex in "[a-f0-9]{0,64}",
        payload in prop::collection::btree_map(field_name_strategy(), scalar_value_strategy(), 0..=16),
        generated_redactions in prop::collection::vec(field_name_strategy(), 0..=12),
    ) {
        let kind = fuzz_signal_kind(kind_tag);
        let mut redact_fields = generated_redactions;
        if let Some(first_payload_field) = payload.keys().next() {
            redact_fields.push(first_payload_field.clone());
        }

        let policy = policy_allowing(kind, redact_fields.clone());
        let event = event_from_payload(
            kind,
            &trace_id,
            source_epoch,
            &contributor_pubkey_hex,
            &payload,
            false,
        );
        let reordered_event = event_from_payload(
            kind,
            &trace_id,
            source_epoch,
            &contributor_pubkey_hex,
            &payload,
            true,
        );

        let signal = extract_signal(&event, &policy)
            .map_err(|err| TestCaseError::fail(format!("extract failed: {err:?}")))?;
        let repeated = extract_signal(&event, &policy)
            .map_err(|err| TestCaseError::fail(format!("repeat extract failed: {err:?}")))?;
        let reordered = extract_signal(&reordered_event, &policy)
            .map_err(|err| TestCaseError::fail(format!("reordered extract failed: {err:?}")))?;
        let mut reversed_policy = policy.clone();
        reversed_policy.redact_fields.reverse();
        let redaction_reordered = extract_signal(&event, &reversed_policy)
            .map_err(|err| TestCaseError::fail(format!("redaction-order extract failed: {err:?}")))?;

        prop_assert_eq!(&signal, &repeated);
        prop_assert_eq!(&signal, &reordered);
        prop_assert_eq!(&signal, &redaction_reordered);
        prop_assert_eq!(signal.kind, kind);
        prop_assert_eq!(signal.trace_id.as_str(), trace_id.as_str());
        prop_assert_eq!(signal.source_epoch, source_epoch);
        prop_assert_eq!(
            signal.contributor_pubkey_hex.as_str(),
            contributor_pubkey_hex.as_str()
        );
        let expected_payload = expected_redacted_payload(&payload, &redact_fields);
        prop_assert_eq!(&signal.redacted_payload, &expected_payload);
        for field in &redact_fields {
            prop_assert!(!signal.redacted_payload.contains_key(field));
        }
        prop_assert_eq!(signal.signal_id.len(), 64);
        prop_assert!(signal.signal_id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        prop_assert_eq!(signal.payload_hash.len(), 64);
        prop_assert!(signal.payload_hash.bytes().all(|byte| byte.is_ascii_hexdigit()));

        let mut log = ExtractionAuditLog::new();
        log.record_ok(&signal);
        let entries = log.entries();
        prop_assert_eq!(entries.len(), 1);
        prop_assert_eq!(entries[0].signal_id.as_str(), signal.signal_id.as_str());
        prop_assert_eq!(entries[0].trace_id.as_str(), signal.trace_id.as_str());
        prop_assert_eq!(
            entries[0].event_code.as_str(),
            event_codes::SIGNAL_EXTRACTED
        );
    }
}

// ---------------------------------------------------------------------------
// JSONL fixture replay
// ---------------------------------------------------------------------------

#[test]
fn fixture_samples_extract_to_distinct_signals() -> Result<(), String> {
    let path = fixture_path();
    let raw =
        fs::read_to_string(&path).map_err(|e| format!("read fixture {}: {e}", path.display()))?;
    let policy = redacting_policy();
    let mut log = ExtractionAuditLog::new();
    let mut signals: Vec<AtcLocalSignal> = Vec::new();
    let mut ids: BTreeSet<String> = BTreeSet::new();

    for (lineno, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value =
            serde_json::from_str(line).map_err(|e| format!("parse line {lineno}: {e}"))?;
        let sig =
            extract_signal(&v, &policy).map_err(|e| format!("extract line {lineno}: {e:?}"))?;
        // Every sample must redact secret_token.
        assert!(!sig.redacted_payload.contains_key("secret_token"));
        log.record_ok(&sig);
        assert!(
            ids.insert(sig.signal_id.clone()),
            "fixture produced duplicate signal_id at line {lineno}"
        );
        signals.push(sig);
    }

    assert_eq!(signals.len(), 5, "expected 5 fixture samples");
    assert_eq!(log.entries().len(), 5);
    assert_eq!(
        log.entries()[0].event_code.as_str(),
        event_codes::SIGNAL_EXTRACTED
    );
    Ok(())
}

#[test]
fn fixture_replay_is_deterministic() -> Result<(), String> {
    // Replaying the fixture twice yields byte-identical signal_id sequences.
    let path = fixture_path();
    let raw =
        fs::read_to_string(&path).map_err(|e| format!("read fixture {}: {e}", path.display()))?;
    let policy = redacting_policy();

    let run = |label: &str| -> Result<Vec<String>, String> {
        raw.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|line| {
                let v: serde_json::Value =
                    serde_json::from_str(line).map_err(|e| format!("{label}: {e}"))?;
                extract_signal(&v, &policy)
                    .map(|sig| sig.signal_id)
                    .map_err(|e| format!("{label}: {e:?}"))
            })
            .collect()
    };

    let a = run("run-1")?;
    let b = run("run-2")?;
    assert_eq!(a, b, "INV-ATC-EXTRACT-DETERMINISM across fixture replays");
    Ok(())
}
