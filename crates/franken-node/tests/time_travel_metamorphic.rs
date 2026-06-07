//! Metamorphic tests for time-travel engine TraceBuilder step order preservation.
//!
//! Tests the INV-TTR-STEP-ORDER invariant: trace steps are strictly ordered by
//! sequence number and this order is preserved through all builder operations.

use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};
use std::collections::BTreeMap;

use frankenengine_node::capacity_defaults::aliases::MAX_TRACE_STEPS;
use frankenengine_node::replay::time_travel_engine::{
    AuditEntry, DivergenceKind, EnvironmentSnapshot, ReplayEngine, ReplayVerdict, SideEffect,
    TraceBuilder, TraceStep, WorkflowTrace, event_codes,
};
use frankenengine_node::storage::cas::{ContentAddressedStore, content_hash};

/// Create a demo environment for testing.
fn demo_env() -> EnvironmentSnapshot {
    EnvironmentSnapshot::new(
        1_000_000,
        BTreeMap::from([("TEST_KEY".to_string(), "test_value".to_string())]),
        "linux-x86_64",
        "1.0.0",
    )
}

/// Generate arbitrary step data for proptest.
#[derive(Debug, Clone)]
struct StepData {
    input: Vec<u8>,
    output: Vec<u8>,
    side_effects: Vec<SideEffectData>,
    timestamp_ns: u64,
}

impl Arbitrary for StepData {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            prop::collection::vec(any::<u8>(), 0..=100),
            prop::collection::vec(any::<u8>(), 0..=100),
            prop::collection::vec(any::<SideEffectData>(), 0..=4),
            1_000_000_u64..=u64::MAX,
        )
            .prop_map(|(input, output, side_effects, timestamp_ns)| StepData {
                input,
                output,
                side_effects,
                timestamp_ns,
            })
            .boxed()
    }
}

#[derive(Debug, Clone)]
struct SideEffectData {
    kind: String,
    payload: Vec<u8>,
}

impl Arbitrary for SideEffectData {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            prop::collection::vec(any::<u8>(), 0..=8),
            prop::collection::vec(any::<u8>(), 0..=64),
        )
            .prop_map(|(kind_bytes, payload)| SideEffectData {
                kind: format!("effect_{}", hex::encode(kind_bytes)),
                payload,
            })
            .boxed()
    }
}

fn side_effect_from_data(data: &SideEffectData) -> SideEffect {
    SideEffect::new(&data.kind, data.payload.clone())
}

fn generated_environment_strategy() -> impl Strategy<Value = EnvironmentSnapshot> {
    (
        any::<u64>(),
        prop::collection::vec(
            (
                prop::collection::vec(any::<u8>(), 0..=6),
                prop::collection::vec(any::<u8>(), 0..=24),
            ),
            0..=8,
        ),
        prop::collection::vec(any::<u8>(), 1..=6),
        (0_u8..=9, 0_u8..=9, 0_u8..=9),
    )
        .prop_map(
            |(clock_seed_ns, env_pairs, platform_bytes, version_parts)| {
                let env_vars = env_pairs
                    .into_iter()
                    .enumerate()
                    .map(|(index, (key_bytes, value_bytes))| {
                        (
                            format!("KEY_{index}_{}", hex::encode(key_bytes)),
                            hex::encode(value_bytes),
                        )
                    })
                    .collect();

                EnvironmentSnapshot::new(
                    clock_seed_ns,
                    env_vars,
                    &format!("linux-{}", hex::encode(platform_bytes)),
                    &format!(
                        "{}.{}.{}",
                        version_parts.0, version_parts.1, version_parts.2
                    ),
                )
            },
        )
}

fn build_trace_from_steps(
    trace_id: &str,
    workflow_name: &str,
    environment: EnvironmentSnapshot,
    steps_data: &[StepData],
) -> (WorkflowTrace, Vec<AuditEntry>) {
    let mut builder = TraceBuilder::new(trace_id, workflow_name, environment);
    for step_data in steps_data {
        let side_effects = step_data
            .side_effects
            .iter()
            .map(side_effect_from_data)
            .collect();
        builder.record_step(
            step_data.input.clone(),
            step_data.output.clone(),
            side_effects,
            step_data.timestamp_ns,
        );
    }
    builder.build().expect("generated trace should build")
}

fn audit_event_codes(entries: &[AuditEntry]) -> Vec<&str> {
    entries
        .iter()
        .map(|entry| entry.event_code.as_str())
        .collect()
}

fn assert_event_count(codes: &[&str], event_code: &str, expected: usize) {
    assert_eq!(
        codes.iter().filter(|code| **code == event_code).count(),
        expected,
        "expected {expected} {event_code} events in {codes:?}"
    );
}

struct CasReplayFixture {
    _tempdir: tempfile::TempDir,
    cas: ContentAddressedStore,
    trace: WorkflowTrace,
}

fn cas_backed_real_io_trace(trace_id: &str) -> CasReplayFixture {
    let tempdir = tempfile::tempdir().expect("tempdir should be available");
    let cas =
        ContentAddressedStore::with_directory(tempdir.path()).expect("CAS should open in tempdir");
    let empty = cas.put(b"").expect("empty pre-state should store");
    let first_result = cas.put(b"first recorded bytes").expect("first result");
    let second_result = cas.put(b"second recorded bytes").expect("second result");

    let mut builder = TraceBuilder::new(trace_id, "verify-cas", demo_env());
    builder.record_step(
        b"fs.readFile".to_vec(),
        b"first-output".to_vec(),
        vec![SideEffect::recorded(
            "fs_read",
            "cap:fs:/tmp/a",
            empty.clone(),
            first_result.clone(),
            first_result,
            b"first recorded bytes".to_vec(),
        )],
        1_000_010,
    );
    builder.record_step(
        b"http.request".to_vec(),
        b"second-output".to_vec(),
        vec![SideEffect::recorded(
            "http_request",
            "cap:http:example.test",
            empty,
            second_result.clone(),
            second_result,
            b"second recorded bytes".to_vec(),
        )],
        1_000_020,
    );
    let (trace, _) = builder.build().expect("trace should build");

    CasReplayFixture {
        _tempdir: tempdir,
        cas,
        trace,
    }
}

fn assert_audit_json_contract(entries: &[AuditEntry], trace_id: &str) -> serde_json::Value {
    let audit_json = serde_json::to_value(entries).expect("audit telemetry should serialize");
    let audit_entries = audit_json
        .as_array()
        .expect("audit telemetry should be a JSON array");
    assert_eq!(audit_entries.len(), entries.len());

    for entry in audit_entries {
        assert_eq!(entry["trace_id"], trace_id);
        assert!(
            entry["event_code"]
                .as_str()
                .expect("event_code should be a string")
                .starts_with("TTR-")
        );
        assert!(entry["detail"].is_string());
        assert!(entry["timestamp_ns"].as_u64().is_some());
    }

    audit_json
}

fn assert_audit_event_detail(entries: &[AuditEntry], event_code: &str, expected_detail: &str) {
    assert!(
        entries.iter().any(|entry| {
            entry.event_code.as_str() == event_code && entry.detail.contains(expected_detail)
        }),
        "expected {event_code} audit detail containing {expected_detail:?} in {entries:?}"
    );
}

fn one_step_replay_trace(trace_id: &str, side_effects: Vec<SideEffect>) -> WorkflowTrace {
    let mut builder = TraceBuilder::new(trace_id, "divergence-kind-classification", demo_env());
    builder.record_step(
        b"input".to_vec(),
        b"output".to_vec(),
        side_effects,
        1_000_010,
    );
    let (trace, _) = builder.build().expect("trace should build");
    trace
}

fn output_mismatch_replay(
    step: &TraceStep,
    _env: &EnvironmentSnapshot,
) -> (Vec<u8>, Vec<SideEffect>) {
    let mut replayed_output = step.output.clone();
    replayed_output.extend_from_slice(b"-changed");
    (replayed_output, step.side_effects.clone())
}

fn side_effect_mismatch_replay(
    step: &TraceStep,
    _env: &EnvironmentSnapshot,
) -> (Vec<u8>, Vec<SideEffect>) {
    (
        step.output.clone(),
        vec![SideEffect::new("fs_read", b"different-bytes".to_vec())],
    )
}

fn full_mismatch_replay(
    _step: &TraceStep,
    _env: &EnvironmentSnapshot,
) -> (Vec<u8>, Vec<SideEffect>) {
    (
        b"different-output".to_vec(),
        vec![SideEffect::new("http_request", b"different-body".to_vec())],
    )
}

fn clock_drift_replay(step: &TraceStep, _env: &EnvironmentSnapshot) -> (Vec<u8>, Vec<SideEffect>) {
    let mut replayed_effects = step.side_effects.clone();
    for effect in &mut replayed_effects {
        if effect.effect_kind.as_str() == "clock_read" {
            effect.payload = 2_000_000_000_u64.to_le_bytes().to_vec();
            effect.result_hash = content_hash(&effect.payload);
            effect.post_state_hash = content_hash(&effect.payload);
        }
    }
    (step.output.clone(), replayed_effects)
}

#[test]
fn trace_builder_preserves_step_order() {
    let mut runner = TestRunner::default();
    let strategy = prop::collection::vec(any::<StepData>(), 1..=20);

    runner
        .run(&strategy, |steps_data| {
            let trace_id = "metamorphic-order-test";
            let workflow_name = "step-order-preservation";

            // Create builder and add steps in order
            let mut builder = TraceBuilder::new(trace_id, workflow_name, demo_env());
            let mut expected_seqs = Vec::new();

            for (expected_seq, step_data) in steps_data.iter().enumerate() {
                let side_effects: Vec<SideEffect> = step_data
                    .side_effects
                    .iter()
                    .map(side_effect_from_data)
                    .collect();
                let actual_seq = builder.record_step(
                    step_data.input.clone(),
                    step_data.output.clone(),
                    side_effects,
                    step_data.timestamp_ns,
                );

                // Verify sequence number assignment is correct
                prop_assert_eq!(actual_seq, expected_seq as u64);
                expected_seqs.push(expected_seq as u64);

                // Verify step count increases monotonically
                prop_assert_eq!(builder.step_count(), expected_seq + 1);
            }

            // Build the final trace
            let (trace, capture_audit) = builder.build().expect("trace should build successfully");

            // METAMORPHIC PROPERTY: Order preservation
            // The final trace must have exactly the same number of steps
            prop_assert_eq!(trace.steps.len(), steps_data.len());

            // Each step's sequence number and payload must match its position in the vector.
            for (index, step) in trace.steps.iter().enumerate() {
                let expected_step = &steps_data[index];
                let expected_side_effects: Vec<SideEffect> = expected_step
                    .side_effects
                    .iter()
                    .map(side_effect_from_data)
                    .collect();
                prop_assert_eq!(
                    step.seq,
                    index as u64,
                    "Step at index {} has seq {}, expected {}",
                    index,
                    step.seq,
                    index
                );
                prop_assert_eq!(&step.input, &expected_step.input);
                prop_assert_eq!(&step.output, &expected_step.output);
                prop_assert_eq!(&step.side_effects, &expected_side_effects);
                prop_assert_eq!(step.timestamp_ns, expected_step.timestamp_ns);
            }

            let capture_codes = audit_event_codes(&capture_audit);
            prop_assert_eq!(capture_codes.first().copied(), Some(event_codes::TTR_001));
            prop_assert!(capture_codes.contains(&event_codes::TTR_008));
            prop_assert_eq!(
                capture_codes
                    .iter()
                    .filter(|code| **code == event_codes::TTR_002)
                    .count(),
                steps_data.len()
            );
            prop_assert!(capture_codes.contains(&event_codes::TTR_003));
            prop_assert!(capture_codes.contains(&event_codes::TTR_009));

            // Additional invariant: sequence numbers must be strictly ascending
            let seq_numbers: Vec<u64> = trace.steps.iter().map(|s| s.seq).collect();
            for window in seq_numbers.windows(2) {
                prop_assert!(
                    window[1] == window[0] + 1,
                    "Sequence numbers not consecutive: {} -> {}",
                    window[0],
                    window[1]
                );
            }

            // Additional invariant: no gaps in sequence numbering
            let first_seq = trace.steps.first().map(|s| s.seq).unwrap_or(0);
            let last_seq = trace.steps.last().map(|s| s.seq).unwrap_or(0);
            let expected_len = if trace.steps.is_empty() {
                0
            } else {
                last_seq.saturating_sub(first_seq).saturating_add(1) as usize
            };
            prop_assert_eq!(
                expected_len,
                trace.steps.len(),
                "Sequence numbers have gaps: range {}..={} vs {} steps",
                first_seq,
                last_seq,
                trace.steps.len()
            );
            Ok(())
        })
        .expect("step order property should hold");
}

#[test]
fn workflow_trace_json_round_trip_identity_for_generated_inputs() {
    let mut runner = TestRunner::new(Config::with_cases(32));
    let strategy = (
        generated_environment_strategy(),
        prop::collection::vec(any::<StepData>(), 1..=12),
    );

    runner
        .run(&strategy, |(environment, steps_data)| {
            let (trace, capture_audit) = build_trace_from_steps(
                "bd-10xmk-roundtrip",
                "serde-round-trip-identity",
                environment,
                &steps_data,
            );

            let encoded =
                serde_json::to_string(&trace).expect("workflow trace should serialize to JSON");
            let decoded: WorkflowTrace =
                serde_json::from_str(&encoded).expect("workflow trace JSON should decode");
            let recoded = serde_json::to_string(&decoded)
                .expect("decoded workflow trace should serialize to JSON");

            prop_assert_eq!(&decoded, &trace);
            prop_assert_eq!(recoded, encoded);
            prop_assert!(decoded.validate().is_ok());
            prop_assert_eq!(decoded.canonical_digest(), trace.trace_digest);

            let capture_codes = audit_event_codes(&capture_audit);
            prop_assert!(capture_codes.contains(&event_codes::TTR_001));
            prop_assert!(capture_codes.contains(&event_codes::TTR_003));
            prop_assert!(capture_codes.contains(&event_codes::TTR_009));
            prop_assert_eq!(
                capture_codes
                    .iter()
                    .filter(|code| **code == event_codes::TTR_002)
                    .count(),
                steps_data.len()
            );

            Ok(())
        })
        .expect("workflow trace JSON round-trip identity should hold");
}

#[test]
fn trace_step_and_environment_json_round_trip_identity_for_generated_inputs() {
    let mut runner = TestRunner::new(Config::with_cases(32));
    let strategy = (any::<StepData>(), generated_environment_strategy());

    runner
        .run(&strategy, |(step_data, environment)| {
            let side_effects = step_data
                .side_effects
                .iter()
                .map(side_effect_from_data)
                .collect();
            let step = TraceStep::new(
                u64::MAX.saturating_sub(7),
                step_data.input,
                step_data.output,
                side_effects,
                step_data.timestamp_ns,
            );

            let step_json =
                serde_json::to_string(&step).expect("trace step should serialize to JSON");
            let decoded_step: TraceStep =
                serde_json::from_str(&step_json).expect("trace step JSON should decode");
            prop_assert_eq!(&decoded_step, &step);
            prop_assert_eq!(
                serde_json::to_string(&decoded_step)
                    .expect("decoded trace step should serialize to JSON"),
                step_json
            );

            let env_json = serde_json::to_string(&environment)
                .expect("environment snapshot should serialize to JSON");
            let decoded_env: EnvironmentSnapshot =
                serde_json::from_str(&env_json).expect("environment JSON should decode");
            prop_assert_eq!(&decoded_env, &environment);
            prop_assert_eq!(
                serde_json::to_string(&decoded_env)
                    .expect("decoded environment should serialize to JSON"),
                env_json
            );

            Ok(())
        })
        .expect("trace step and environment JSON round-trip identity should hold");
}

#[test]
fn replay_round_trip_identity_emits_capture_and_replay_telemetry() {
    let mut builder = TraceBuilder::new(
        "bd-10xmk-telemetry",
        "serde-round-trip-telemetry",
        demo_env(),
    );
    builder.record_step(
        b"first-input".to_vec(),
        b"first-output".to_vec(),
        vec![SideEffect::new("file_write", b"/tmp/trace".to_vec())],
        1_000_010,
    );
    builder.record_step(
        b"second-input".to_vec(),
        b"second-output".to_vec(),
        vec![SideEffect::new("network_call", b"POST /audit".to_vec())],
        1_000_020,
    );

    let (trace, capture_audit) = builder.build().expect("trace should build");
    let trace_json = serde_json::to_string(&trace).expect("trace should serialize");
    let decoded_trace: WorkflowTrace =
        serde_json::from_str(&trace_json).expect("trace should deserialize");

    let capture_codes = audit_event_codes(&capture_audit);
    assert!(capture_codes.contains(&event_codes::TTR_001));
    assert!(capture_codes.contains(&event_codes::TTR_008));
    assert_event_count(&capture_codes, event_codes::TTR_002, 2);
    assert!(capture_codes.contains(&event_codes::TTR_003));
    assert!(capture_codes.contains(&event_codes::TTR_009));

    let mut engine = ReplayEngine::new();
    engine
        .register_trace(decoded_trace)
        .expect("deserialized trace should register");
    let result = engine
        .replay_fixture_identity("bd-10xmk-telemetry")
        .expect("fixture replay should succeed");

    assert_eq!(result.verdict, ReplayVerdict::Identical);
    assert_eq!(result.steps_replayed, 2);
    assert!(result.divergences.is_empty());

    let replay_codes = audit_event_codes(engine.audit_log());
    assert!(replay_codes.contains(&event_codes::TTR_004));
    assert_event_count(&replay_codes, event_codes::TTR_005, 2);
    assert!(replay_codes.contains(&event_codes::TTR_007));

    let result_json = serde_json::to_string(&result).expect("replay result should serialize");
    let decoded_result: serde_json::Value =
        serde_json::from_str(&result_json).expect("replay result JSON should decode");
    assert_eq!(decoded_result["trace_id"], "bd-10xmk-telemetry");
    assert_eq!(decoded_result["verdict"], "identical");

    let audit_json =
        serde_json::to_string(engine.audit_log()).expect("audit telemetry should serialize");
    let decoded_audit: serde_json::Value =
        serde_json::from_str(&audit_json).expect("audit telemetry JSON should decode");
    assert_eq!(
        decoded_audit
            .as_array()
            .expect("audit telemetry should be an array")
            .len(),
        engine.audit_log().len()
    );
}

#[test]
fn verify_replay_from_cas_serves_recorded_bytes_as_identical() {
    let CasReplayFixture {
        _tempdir,
        cas,
        trace,
    } = cas_backed_real_io_trace("verify-cas-identical");

    let mut engine = ReplayEngine::new();
    engine.register_trace(trace).expect("trace should register");
    let result = engine
        .verify_replay_from_cas("verify-cas-identical", &cas)
        .expect("CAS-backed verify replay should succeed");

    assert_eq!(result.verdict, ReplayVerdict::Identical);
    assert_eq!(result.steps_replayed, 2);
    assert!(result.divergences.is_empty());

    let replay_codes = audit_event_codes(engine.audit_log());
    assert!(replay_codes.contains(&event_codes::TTR_004));
    assert_event_count(&replay_codes, event_codes::TTR_005, 2);
    assert_eq!(replay_codes.last().copied(), Some(event_codes::TTR_007));
    assert_event_count(&replay_codes, event_codes::TTR_006, 0);
    assert_audit_event_detail(engine.audit_log(), event_codes::TTR_005, "Step 0 identical");
    assert_audit_event_detail(engine.audit_log(), event_codes::TTR_005, "Step 1 identical");

    let audit_json = assert_audit_json_contract(engine.audit_log(), "verify-cas-identical");
    assert_eq!(
        audit_json
            .as_array()
            .expect("audit telemetry should be an array")
            .last()
            .expect("audit telemetry should include replay completion")["detail"],
        "Replay completed: verdict=identical"
    );
}

#[test]
fn verify_replay_from_cas_mutated_recorded_byte_diverges_at_step() {
    let CasReplayFixture {
        _tempdir,
        cas,
        mut trace,
    } = cas_backed_real_io_trace("verify-cas-mutated");
    let byte = trace
        .steps
        .get_mut(1)
        .and_then(|step| step.side_effects.first_mut())
        .and_then(|effect| effect.payload.first_mut())
        .expect("fixture should contain a second-step side-effect payload byte");
    *byte ^= 0x01;
    let trace = trace.with_canonical_digest();

    let mut engine = ReplayEngine::new();
    engine
        .register_trace(trace)
        .expect("mutated trace should still register");
    let result = engine
        .verify_replay_from_cas("verify-cas-mutated", &cas)
        .expect("CAS-backed verify replay should classify the mismatch");

    assert_eq!(result.verdict, ReplayVerdict::Diverged(1));
    assert_eq!(result.divergences.len(), 1);
    assert_eq!(result.divergences[0].step_seq, 1);
    assert_eq!(
        result.divergences[0].kind,
        DivergenceKind::SideEffectMismatch
    );
    assert!(
        result.divergences[0]
            .explanation
            .contains("side_effect_mismatch")
    );

    let replay_codes = audit_event_codes(engine.audit_log());
    assert!(replay_codes.contains(&event_codes::TTR_004));
    assert_event_count(&replay_codes, event_codes::TTR_005, 1);
    assert_event_count(&replay_codes, event_codes::TTR_006, 1);
    assert_eq!(replay_codes.last().copied(), Some(event_codes::TTR_007));
    assert_audit_event_detail(engine.audit_log(), event_codes::TTR_005, "Step 0 identical");
    assert_audit_event_detail(engine.audit_log(), event_codes::TTR_006, "Step 1 diverged");

    let audit_json = assert_audit_json_contract(engine.audit_log(), "verify-cas-mutated");
    assert!(
        audit_json
            .as_array()
            .expect("audit telemetry should be an array")
            .iter()
            .any(|entry| entry["detail"]
                .as_str()
                .expect("detail should be a string")
                .contains("effects_match=false"))
    );
}

#[test]
fn typed_side_effect_json_round_trip_preserves_capability_and_hashes() {
    let effect = SideEffect::recorded(
        "fs_write",
        "cap:fs:workspace-report",
        content_hash(b"report-before"),
        content_hash(b"write-ok"),
        content_hash(b"report-after"),
        b"write-ok".to_vec(),
    );

    let encoded = serde_json::to_string(&effect).expect("side effect should serialize");
    let decoded: SideEffect =
        serde_json::from_str(&encoded).expect("side effect JSON should decode");

    assert_eq!(decoded, effect);
    assert_eq!(decoded.effect_kind, "fs_write");
    assert_eq!(decoded.capability_ref, "cap:fs:workspace-report");
    assert_eq!(decoded.pre_state_hash, content_hash(b"report-before"));
    assert_eq!(decoded.result_hash, content_hash(b"write-ok"));
    assert_eq!(decoded.post_state_hash, content_hash(b"report-after"));
    assert_eq!(decoded.payload, b"write-ok".to_vec());
}

#[test]
fn replay_divergence_kind_classifications_cover_output_effect_full_and_clock() {
    let cases: [(
        &str,
        fn(&TraceStep, &EnvironmentSnapshot) -> (Vec<u8>, Vec<SideEffect>),
        DivergenceKind,
        &str,
    ); 3] = [
        (
            "classification-output-mismatch",
            output_mismatch_replay,
            DivergenceKind::OutputMismatch,
            "output_mismatch",
        ),
        (
            "classification-side-effect-mismatch",
            side_effect_mismatch_replay,
            DivergenceKind::SideEffectMismatch,
            "side_effect_mismatch",
        ),
        (
            "classification-full-mismatch",
            full_mismatch_replay,
            DivergenceKind::FullMismatch,
            "full_mismatch",
        ),
    ];

    for (trace_id, replay_fn, expected_kind, expected_kind_label) in cases {
        let trace = one_step_replay_trace(
            trace_id,
            vec![SideEffect::new("fs_read", b"recorded-bytes".to_vec())],
        );
        let mut engine = ReplayEngine::new();
        engine.register_trace(trace).expect("trace should register");
        let result = engine
            .replay(trace_id, replay_fn)
            .expect("replay should classify divergence");

        assert_eq!(result.verdict, ReplayVerdict::Diverged(1));
        assert_eq!(result.divergences.len(), 1);
        assert_eq!(result.divergences[0].step_seq, 0);
        assert_eq!(result.divergences[0].kind, expected_kind);
        assert!(
            result.divergences[0]
                .explanation
                .contains(expected_kind_label)
        );
    }

    let original_clock_ns = 1_000_000_u64;
    let clock_payload = original_clock_ns.to_le_bytes().to_vec();
    let trace = one_step_replay_trace(
        "classification-clock-drift",
        vec![SideEffect::recorded(
            "clock_read",
            "cap:clock:monotonic",
            content_hash(b""),
            content_hash(&clock_payload),
            content_hash(&clock_payload),
            clock_payload,
        )],
    );
    let mut engine = ReplayEngine::new();
    engine.register_trace(trace).expect("trace should register");
    let result = engine
        .replay("classification-clock-drift", clock_drift_replay)
        .expect("clock replay should classify drift");

    assert_eq!(result.verdict, ReplayVerdict::Diverged(1));
    let clock_drift = result
        .divergences
        .iter()
        .find(|divergence| {
            matches!(
                &divergence.kind,
                DivergenceKind::ClockDrift {
                    expected_ns,
                    actual_ns,
                    ..
                } if *expected_ns == original_clock_ns && *actual_ns == 2_000_000_000
            )
        })
        .expect("clock drift divergence should be recorded");
    assert_eq!(clock_drift.step_seq, 0);
    assert_audit_event_detail(
        engine.audit_log(),
        event_codes::TTR_006,
        "Clock drift detected",
    );
}

#[test]
fn workflow_trace_rejects_reordered_and_gapped_step_sequences() {
    let mut builder = TraceBuilder::new("sequence-negative", "sequence-negative", demo_env());
    builder.record_step(b"input-0".to_vec(), b"output-0".to_vec(), vec![], 1_000_000);
    builder.record_step(b"input-1".to_vec(), b"output-1".to_vec(), vec![], 1_000_001);
    builder.record_step(b"input-2".to_vec(), b"output-2".to_vec(), vec![], 1_000_002);
    let (trace, _) = builder.build().expect("trace should build");

    let mut reordered = trace.clone();
    reordered.steps.swap(0, 1);
    reordered = reordered.with_canonical_digest();
    let reordered_error = reordered
        .validate()
        .expect_err("reordered sequence must be rejected")
        .to_string();
    assert!(
        reordered_error.contains("ERR_TTR_SEQ_GAP"),
        "unexpected reordered trace error: {reordered_error}"
    );

    let mut gapped = trace;
    gapped.steps.remove(1);
    gapped = gapped.with_canonical_digest();
    let gapped_error = gapped
        .validate()
        .expect_err("gapped sequence must be rejected")
        .to_string();
    assert!(
        gapped_error.contains("ERR_TTR_SEQ_GAP"),
        "unexpected gapped trace error: {gapped_error}"
    );
}

#[test]
fn empty_trace_builder_fails_correctly() {
    let mut runner = TestRunner::default();

    runner
        .run(&Just(()), |_| {
            let builder = TraceBuilder::new("empty-test", "empty-workflow", demo_env());

            // Empty builder should fail to build
            let result = builder.build();
            prop_assert!(result.is_err());

            // Should be specifically an EmptyTrace error
            match result {
                Err(e) => {
                    let error_str = format!("{:?}", e);
                    prop_assert!(
                        error_str.contains("EmptyTrace") || error_str.contains("empty"),
                        "Expected EmptyTrace error, got: {}",
                        error_str
                    );
                }
                Ok(_) => {
                    return Err(proptest::test_runner::TestCaseError::fail(
                        "Empty trace should not build successfully",
                    ));
                }
            }
            Ok(())
        })
        .expect("empty builder property should hold");
}

#[test]
fn trace_builder_respects_max_capacity() {
    let trace_id = "capacity-test";
    let workflow_name = "max-capacity-preservation";
    let mut builder = TraceBuilder::new(trace_id, workflow_name, demo_env());

    let extra_steps = 10;
    let total_attempts = MAX_TRACE_STEPS + extra_steps;

    for i in 0..total_attempts {
        let input = vec![i as u8];
        let output = vec![(i * 2) as u8];
        let timestamp = 1_000_000 + i as u64;

        let seq = builder.record_step(input, output, vec![], timestamp);

        assert_eq!(seq, i as u64);
        assert_eq!(builder.step_count(), std::cmp::min(i + 1, MAX_TRACE_STEPS));
    }

    let (trace, _audit_log) = builder
        .build()
        .expect("trace should build successfully even when capped");

    assert_eq!(trace.steps.len(), MAX_TRACE_STEPS);

    // The retained bounded window must be reindexed from zero after old steps
    // are evicted, so validation has no sequence gaps.
    for (index, step) in trace.steps.iter().enumerate() {
        assert_eq!(
            step.seq, index as u64,
            "Capped trace step at index {index} has seq {}, expected {index}",
            step.seq
        );
    }

    assert_eq!(trace.steps[0].seq, 0);
    assert_eq!(
        trace.steps[MAX_TRACE_STEPS - 1].seq,
        (MAX_TRACE_STEPS - 1) as u64
    );
    assert_eq!(
        trace.steps[MAX_TRACE_STEPS - 1].timestamp_ns,
        1_000_000 + (total_attempts - 1) as u64,
        "bounded trace should retain the newest step after overflow"
    );
    assert!(trace.validate().is_ok());
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    /// Simple unit test to verify the metamorphic test infrastructure works.
    #[test]
    fn test_demo_env_creation() {
        let env = demo_env();
        assert_eq!(env.platform, "linux-x86_64");
        assert_eq!(env.clock_seed_ns, 1_000_000);
    }

    /// Unit test for single step ordering.
    #[test]
    fn test_single_step_order() {
        let mut builder = TraceBuilder::new("single-test", "single-workflow", demo_env());

        let seq = builder.record_step(vec![1, 2, 3], vec![4, 5, 6], vec![], 2_000_000);

        assert_eq!(seq, 0);
        assert_eq!(builder.step_count(), 1);

        let (trace, _) = builder.build().expect("single step trace should build");
        assert_eq!(trace.steps.len(), 1);
        assert_eq!(trace.steps[0].seq, 0);
    }
}
