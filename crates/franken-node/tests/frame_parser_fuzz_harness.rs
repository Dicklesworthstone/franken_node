//! Structure-aware fuzz harness for connector frame parser guardrails.
//!
//! The production frame parser is a bounded resource-accounting guard over
//! already-decoded control-channel frames. This harness models the narrow wire
//! boundary immediately before that guard, then feeds decoded resource claims to
//! `connector::frame_parser::check_frame` without allocating declared payloads.

use frankenengine_node::connector::frame_parser::{
    DecodeAuditEntry, DecodeVerdict, FrameInput, GuardrailViolation, ParserConfig, ParserError,
    check_batch, check_frame,
};
use frankenengine_node::tools::replay_bundle::{
    EventType, RawEvent, generate_replay_bundle, to_canonical_json,
};
use serde_json::Value;

const TEST_TAG: u8 = 0xA7;
const WIRE_HEADER_LEN: usize = 5;

#[derive(Debug)]
enum HarnessOutcome {
    Parsed {
        verdict: DecodeVerdict,
        audit: DecodeAuditEntry,
    },
    ParserError(ParserError),
    WireRejected(WireReject),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WireReject {
    MalformedLengthPrefix,
    TruncatedPayload { declared: u32, actual: usize },
    HeaderTooShort { declared: u32 },
    InvalidTag { tag: u8 },
    OverlappingFields { id_len: usize, available: usize },
}

fn fuzz_config() -> ParserConfig {
    ParserConfig {
        max_frame_bytes: 64,
        max_nesting_depth: 4,
        max_decode_cpu_ms: 10,
    }
}

fn push_len_prefix(out: &mut Vec<u8>, len: u32) {
    out.extend_from_slice(&len.to_be_bytes());
}

fn len_u32(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX)
}

fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn encode_structured_frame(
    tag: u8,
    frame_id: &[u8],
    depth: u8,
    cpu_ms: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(tag);
    body.push(u8::try_from(frame_id.len()).unwrap_or(u8::MAX));
    body.push(depth);
    body.extend_from_slice(&cpu_ms.to_be_bytes());
    body.extend_from_slice(frame_id);
    body.extend_from_slice(payload);

    let mut encoded = Vec::new();
    push_len_prefix(&mut encoded, len_u32(body.len()));
    encoded.extend_from_slice(&body);
    encoded
}

fn encode_with_declared_len(declared_len: u32, body: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    push_len_prefix(&mut encoded, declared_len);
    encoded.extend_from_slice(body);
    encoded
}

fn replay_json_depth(value: &Value) -> usize {
    match value {
        Value::Array(items) => items
            .iter()
            .map(replay_json_depth)
            .max()
            .unwrap_or(0)
            .saturating_add(1),
        Value::Object(fields) => fields
            .values()
            .map(replay_json_depth)
            .max()
            .unwrap_or(0)
            .saturating_add(1),
        _ => 1,
    }
}

fn replay_claimed_depth(payload: &[u8]) -> u8 {
    serde_json::from_slice::<Value>(payload).map_or(1, |value| {
        u8::try_from(replay_json_depth(&value).min(usize::from(u8::MAX))).expect("depth capped")
    })
}

fn replay_claimed_cpu_ms(payload: &[u8]) -> u16 {
    u16::try_from(payload.len().min(9)).expect("payload length capped below parser cpu limit")
}

fn encode_replay_frame(frame_id: &str, payload: &[u8]) -> Vec<u8> {
    encode_structured_frame(
        TEST_TAG,
        frame_id.as_bytes(),
        replay_claimed_depth(payload),
        replay_claimed_cpu_ms(payload),
        payload,
    )
}

fn replay_event_frame_payload(sequence_number: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "e": sequence_number,
        "t": "policy_eval"
    }))
    .expect("small replay event payload should serialize")
}

fn replay_bundle_json_frame() -> Vec<u8> {
    let events = vec![
        RawEvent::new(
            "2026-02-20T10:00:00.000001Z",
            EventType::ExternalSignal,
            serde_json::json!({"signal":"anomaly","severity":"high"}),
        )
        .with_state_snapshot(serde_json::json!({"epoch":7_u64,"mode":"strict"}))
        .with_policy_version("1.2.3"),
        RawEvent::new(
            "2026-02-20T10:00:00.000002Z",
            EventType::PolicyEval,
            serde_json::json!({"decision":"quarantine","confidence":91_u64}),
        )
        .with_causal_parent(1),
    ];
    let bundle = generate_replay_bundle("INC-FRAME-FUZZ", &events)
        .expect("replay bundle grammar should build");
    let canonical_json = to_canonical_json(&bundle).expect("bundle should canonicalize");
    encode_replay_frame("replay:bundle", canonical_json.as_bytes())
}

fn run_harness(input: &[u8]) -> HarnessOutcome {
    if input.len() < 4 {
        return HarnessOutcome::WireRejected(WireReject::MalformedLengthPrefix);
    }

    let declared_len = u32::from_be_bytes(input[0..4].try_into().expect("prefix length checked"));
    let config = fuzz_config();
    let claimed_frame_len = u64::from(declared_len).saturating_add(4);

    if claimed_frame_len >= config.max_frame_bytes {
        let frame = FrameInput {
            frame_id: format!("declared-len-{declared_len}"),
            raw_bytes_len: claimed_frame_len,
            nesting_depth: 0,
            decode_cpu_ms: 0,
        };
        return frame_parser_result(check_frame(&frame, &config, "fuzz-seed"));
    }

    let actual_body_len = input.len().saturating_sub(4);
    let declared_body_len = usize::try_from(declared_len).unwrap_or(usize::MAX);
    if actual_body_len < declared_body_len {
        return HarnessOutcome::WireRejected(WireReject::TruncatedPayload {
            declared: declared_len,
            actual: actual_body_len,
        });
    }

    let body = &input[4..4 + declared_body_len];
    if body.len() < WIRE_HEADER_LEN {
        return HarnessOutcome::WireRejected(WireReject::HeaderTooShort {
            declared: declared_len,
        });
    }

    let tag = body[0];
    if tag != TEST_TAG {
        return HarnessOutcome::WireRejected(WireReject::InvalidTag { tag });
    }

    let id_len = usize::from(body[1]);
    let available_after_header = body.len().saturating_sub(WIRE_HEADER_LEN);
    if id_len > available_after_header {
        return HarnessOutcome::WireRejected(WireReject::OverlappingFields {
            id_len,
            available: available_after_header,
        });
    }

    let depth = u32::from(body[2]);
    let cpu_ms = u64::from(u16::from_be_bytes([body[3], body[4]]));
    let frame_id_bytes = &body[WIRE_HEADER_LEN..WIRE_HEADER_LEN + id_len];
    let frame_id = String::from_utf8_lossy(frame_id_bytes).into_owned();
    let frame = FrameInput {
        frame_id,
        raw_bytes_len: len_u64(input.len()),
        nesting_depth: depth,
        decode_cpu_ms: cpu_ms,
    };

    frame_parser_result(check_frame(&frame, &config, "fuzz-seed"))
}

fn frame_parser_result(
    result: Result<(DecodeVerdict, DecodeAuditEntry), ParserError>,
) -> HarnessOutcome {
    match result {
        Ok((verdict, audit)) => HarnessOutcome::Parsed { verdict, audit },
        Err(error) => HarnessOutcome::ParserError(error),
    }
}

fn seed_corpus() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "valid-minimal",
            encode_structured_frame(TEST_TAG, b"ok", 1, 1, b"payload"),
        ),
        ("malformed-length-prefix", vec![0x00, 0x01, 0x02]),
        (
            "truncated-payload",
            encode_with_declared_len(12, &[TEST_TAG, 1, 1]),
        ),
        ("huge-length-field", encode_with_declared_len(u32::MAX, &[])),
        (
            "invalid-tag-byte",
            encode_structured_frame(0x00, b"bad-tag", 1, 1, b"payload"),
        ),
        (
            "overlapping-fields",
            encode_with_declared_len(6, &[TEST_TAG, 4, 1, 0, 1, b'x']),
        ),
        (
            "empty-frame-id",
            encode_structured_frame(TEST_TAG, b"", 1, 1, b"payload"),
        ),
        (
            "depth-and-cpu-boundary",
            encode_structured_frame(TEST_TAG, b"busy", 4, 10, b"x"),
        ),
        (
            "replay-event-valid",
            encode_replay_frame("r:1", &replay_event_frame_payload(1)),
        ),
        (
            "replay-frame-id-nul",
            encode_replay_frame("r:\0bad", &replay_event_frame_payload(2)),
        ),
        ("replay-bundle-json-size-guard", replay_bundle_json_frame()),
    ]
}

#[test]
fn seed_corpus_covers_required_frame_parser_fuzz_shapes() {
    let seeds = seed_corpus();

    assert!(seeds.len() >= 6);
    for required in [
        "malformed-length-prefix",
        "truncated-payload",
        "huge-length-field",
        "invalid-tag-byte",
        "overlapping-fields",
        "empty-frame-id",
        "replay-event-valid",
        "replay-frame-id-nul",
        "replay-bundle-json-size-guard",
    ] {
        assert!(
            seeds.iter().any(|(name, _)| *name == required),
            "missing required seed {required}"
        );
    }
}

#[test]
fn malformed_length_prefix_is_rejected_before_frame_guard() {
    let HarnessOutcome::WireRejected(reason) = run_harness(&[0x00, 0x01, 0x02]) else {
        panic!("short length prefix must be rejected by wire harness");
    };

    assert_eq!(reason, WireReject::MalformedLengthPrefix);
}

#[test]
fn truncated_payload_is_rejected_without_trusting_declared_body() {
    let input = encode_with_declared_len(12, &[TEST_TAG, 1, 1]);
    let HarnessOutcome::WireRejected(reason) = run_harness(&input) else {
        panic!("truncated body must be rejected before parser guard");
    };

    assert_eq!(
        reason,
        WireReject::TruncatedPayload {
            declared: 12,
            actual: 3,
        }
    );
}

#[test]
fn huge_length_field_hits_size_guard_without_allocating_payload() {
    let input = encode_with_declared_len(u32::MAX, &[]);
    let HarnessOutcome::Parsed { verdict, audit } = run_harness(&input) else {
        panic!("huge declared length should be converted into bounded parser input");
    };

    assert!(!verdict.allowed);
    assert_eq!(audit.verdict, "BLOCK");
    assert!(verdict.violations.iter().any(|violation| matches!(
        violation,
        GuardrailViolation::SizeExceeded { actual, limit }
            if *actual == u64::from(u32::MAX).saturating_add(4)
                && *limit == fuzz_config().max_frame_bytes
    )));
}

#[test]
fn invalid_tag_byte_is_rejected_before_resource_accounting() {
    let input = encode_structured_frame(0x00, b"bad-tag", 1, 1, b"payload");
    let HarnessOutcome::WireRejected(reason) = run_harness(&input) else {
        panic!("invalid tag should not reach frame parser guard");
    };

    assert_eq!(reason, WireReject::InvalidTag { tag: 0x00 });
}

#[test]
fn overlapping_field_lengths_are_rejected_before_id_decode() {
    let input = encode_with_declared_len(6, &[TEST_TAG, 4, 1, 0, 1, b'x']);
    let HarnessOutcome::WireRejected(reason) = run_harness(&input) else {
        panic!("overlapping id field should be rejected by wire harness");
    };

    assert_eq!(
        reason,
        WireReject::OverlappingFields {
            id_len: 4,
            available: 1,
        }
    );
}

#[test]
fn empty_frame_id_reaches_actual_malformed_frame_guardrail() {
    let input = encode_structured_frame(TEST_TAG, b"", 1, 1, b"payload");
    let HarnessOutcome::ParserError(error) = run_harness(&input) else {
        panic!("empty frame id should be rejected by actual parser guard");
    };

    assert_eq!(error.code(), "BPG_MALFORMED_FRAME");
    assert!(error.to_string().contains("frame_id must not be empty"));
}

#[test]
fn valid_structured_seed_preserves_audit_and_resource_usage() {
    let input = encode_structured_frame(TEST_TAG, b"ok", 1, 1, b"payload");
    let HarnessOutcome::Parsed { verdict, audit } = run_harness(&input) else {
        panic!("valid structured seed should reach parser guard");
    };

    assert!(verdict.allowed);
    assert!(verdict.violations.is_empty());
    assert_eq!(verdict.frame_id, "ok");
    assert_eq!(verdict.resource_usage.bytes_parsed, len_u64(input.len()));
    assert_eq!(audit.frame_id, "ok");
    assert_eq!(audit.verdict, "ALLOW");
}

#[test]
fn depth_and_cpu_boundary_seed_is_fail_closed() {
    let input = encode_structured_frame(TEST_TAG, b"busy", 4, 10, b"x");
    let HarnessOutcome::Parsed { verdict, audit } = run_harness(&input) else {
        panic!("boundary seed should reach parser guard");
    };

    assert!(!verdict.allowed);
    assert_eq!(audit.verdict, "BLOCK");
    assert!(
        verdict
            .violations
            .iter()
            .any(|violation| matches!(violation, GuardrailViolation::DepthExceeded { .. }))
    );
    assert!(
        verdict
            .violations
            .iter()
            .any(|violation| matches!(violation, GuardrailViolation::CpuExceeded { .. }))
    );
}

#[test]
fn batch_harness_preserves_seed_order_for_parser_reachable_frames() {
    let frames = seed_corpus()
        .into_iter()
        .filter_map(|(name, bytes)| match run_harness(&bytes) {
            HarnessOutcome::Parsed { verdict, .. } => Some(FrameInput {
                frame_id: format!("batch-{name}"),
                raw_bytes_len: verdict.resource_usage.bytes_parsed,
                nesting_depth: verdict.resource_usage.nesting_depth,
                decode_cpu_ms: verdict.resource_usage.cpu_ms,
            }),
            HarnessOutcome::ParserError(_) | HarnessOutcome::WireRejected(_) => None,
        })
        .collect::<Vec<_>>();

    let results = check_batch(&frames, &fuzz_config(), "batch-fuzz-seed")
        .expect("parser-reachable seeds should batch-check");

    assert_eq!(results.len(), frames.len());
    for (idx, (verdict, audit)) in results.iter().enumerate() {
        assert_eq!(verdict.frame_id, frames[idx].frame_id);
        assert_eq!(audit.frame_id, frames[idx].frame_id);
    }
}

#[test]
fn replay_event_wire_grammar_reaches_parser_with_allow_verdict() {
    let payload = replay_event_frame_payload(7);
    let input = encode_replay_frame("r:7", &payload);
    let HarnessOutcome::Parsed { verdict, audit } = run_harness(&input) else {
        panic!("valid replay event frame should reach parser guard");
    };

    assert!(verdict.allowed);
    assert!(verdict.violations.is_empty());
    assert_eq!(verdict.frame_id, "r:7");
    assert_eq!(verdict.resource_usage.bytes_parsed, len_u64(input.len()));
    assert_eq!(
        verdict.resource_usage.nesting_depth,
        u32::from(replay_claimed_depth(&payload))
    );
    assert_eq!(audit.verdict, "ALLOW");
}

#[test]
fn replay_frame_id_with_nul_is_rejected_by_actual_parser_guard() {
    let input = encode_replay_frame("r:\0bad", &replay_event_frame_payload(8));
    let HarnessOutcome::ParserError(error) = run_harness(&input) else {
        panic!("NUL-bearing replay frame id should be rejected by parser guard");
    };

    assert_eq!(error.code(), "BPG_MALFORMED_FRAME");
    assert!(
        error
            .to_string()
            .contains("frame_id must not contain NUL bytes")
    );
}

#[test]
fn replay_bundle_json_frame_hits_size_guard_before_payload_decode() {
    let input = replay_bundle_json_frame();
    let declared_len = u32::from_be_bytes(input[0..4].try_into().expect("prefix present"));
    assert!(u64::from(declared_len).saturating_add(4) >= fuzz_config().max_frame_bytes);

    let HarnessOutcome::Parsed { verdict, audit } = run_harness(&input) else {
        panic!("large replay bundle JSON frame should hit parser size guard");
    };

    assert!(!verdict.allowed);
    assert_eq!(verdict.frame_id, format!("declared-len-{declared_len}"));
    assert_eq!(audit.verdict, "BLOCK");
    assert!(verdict.violations.iter().any(|violation| matches!(
        violation,
        GuardrailViolation::SizeExceeded { actual, limit }
            if *actual == u64::from(declared_len).saturating_add(4)
                && *limit == fuzz_config().max_frame_bytes
    )));
}
