//! Metamorphic tests for time-travel engine TraceBuilder step order preservation.
//!
//! Tests the INV-TTR-STEP-ORDER invariant: trace steps are strictly ordered by
//! sequence number and this order is preserved through all builder operations.

use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};
use std::collections::BTreeMap;

use frankenengine_node::capacity_defaults::aliases::MAX_TRACE_STEPS;
use frankenengine_node::replay::time_travel_engine::{
    AuditEntry, EnvironmentSnapshot, ReplayEngine, ReplayVerdict, SideEffect, TraceBuilder,
    TraceStep, WorkflowTrace, event_codes,
};

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
