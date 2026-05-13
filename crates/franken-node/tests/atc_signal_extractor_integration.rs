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
    AtcLocalSignal, ExtractionAuditLog, ExtractionError, ExtractionPolicy, SignalKind,
    event_codes, extract_signal,
};
use serde_json::json;
use std::collections::BTreeSet;
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
    let raw =
        sample_event("revocation_hint", "trace-pub-003-replay-audit-correlation-id", 99);
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

// ---------------------------------------------------------------------------
// JSONL fixture replay
// ---------------------------------------------------------------------------

#[test]
fn fixture_samples_extract_to_distinct_signals() {
    let path = fixture_path();
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()));
    let policy = redacting_policy();
    let mut log = ExtractionAuditLog::new();
    let mut signals: Vec<AtcLocalSignal> = Vec::new();
    let mut ids: BTreeSet<String> = BTreeSet::new();

    for (lineno, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("parse line {lineno}: {e}"));
        let sig = extract_signal(&v, &policy)
            .unwrap_or_else(|e| panic!("extract line {lineno}: {e:?}"));
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
    assert_eq!(log.entries()[0].event_code.as_str(), event_codes::SIGNAL_EXTRACTED);
}

#[test]
fn fixture_replay_is_deterministic() {
    // Replaying the fixture twice yields byte-identical signal_id sequences.
    let path = fixture_path();
    let raw = fs::read_to_string(&path).unwrap();
    let policy = redacting_policy();

    let run = |label: &str| -> Vec<String> {
        raw.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|line| {
                let v: serde_json::Value = serde_json::from_str(line).unwrap();
                extract_signal(&v, &policy)
                    .unwrap_or_else(|e| panic!("{label}: {e:?}"))
                    .signal_id
            })
            .collect()
    };

    let a = run("run-1");
    let b = run("run-2");
    assert_eq!(a, b, "INV-ATC-EXTRACT-DETERMINISM across fixture replays");
}
