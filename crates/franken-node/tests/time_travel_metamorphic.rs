//! Metamorphic tests for time-travel engine TraceBuilder step order preservation.
//!
//! Tests the INV-TTR-STEP-ORDER invariant: trace steps are strictly ordered by
//! sequence number and this order is preserved through all builder operations.

use proptest::prelude::*;
use proptest::test_runner::TestRunner;
use std::collections::BTreeMap;

use frankenengine_node::capacity_defaults::aliases::MAX_TRACE_STEPS;
use frankenengine_node::replay::time_travel_engine::{
    EnvironmentSnapshot, TraceBuilder,
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
    timestamp_ns: u64,
}

impl Arbitrary for StepData {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            prop::collection::vec(any::<u8>(), 0..=100),
            prop::collection::vec(any::<u8>(), 0..=100),
            1_000_000_u64..=u64::MAX,
        )
            .prop_map(|(input, output, timestamp_ns)| StepData {
                input,
                output,
                timestamp_ns,
            })
            .boxed()
    }
}

#[test]
fn trace_builder_preserves_step_order() {
    let mut runner = TestRunner::default();
    let strategy = prop::collection::vec(any::<StepData>(), 1..=20);

    runner.run(&strategy, |steps_data| {
        let trace_id = "metamorphic-order-test";
        let workflow_name = "step-order-preservation";

        // Create builder and add steps in order
        let mut builder = TraceBuilder::new(trace_id, workflow_name, demo_env());
        let mut expected_seqs = Vec::new();

        for (expected_seq, step_data) in steps_data.iter().enumerate() {
            let actual_seq = builder.record_step(
                step_data.input.clone(),
                step_data.output.clone(),
                vec![], // no side effects for this test
                step_data.timestamp_ns,
            );

            // Verify sequence number assignment is correct
            prop_assert_eq!(actual_seq, expected_seq as u64);
            expected_seqs.push(expected_seq as u64);

            // Verify step count increases monotonically
            prop_assert_eq!(builder.step_count(), expected_seq + 1);
        }

        // Build the final trace
        let (trace, _audit_log) = builder.build()
            .expect("trace should build successfully");

        // METAMORPHIC PROPERTY: Order preservation
        // The final trace must have exactly the same number of steps
        prop_assert_eq!(trace.steps.len(), steps_data.len());

        // Each step's sequence number must match its position in the vector
        for (index, step) in trace.steps.iter().enumerate() {
            prop_assert_eq!(
                step.seq,
                index as u64,
                "Step at index {} has seq {}, expected {}",
                index,
                step.seq,
                index
            );
        }

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
        let expected_range = first_seq..=last_seq;
        prop_assert_eq!(
            expected_range.len(),
            trace.steps.len(),
            "Sequence numbers have gaps: range {first_seq}..={last_seq} vs {} steps",
            trace.steps.len()
        );
        Ok(())
    })
    .expect("step order property should hold");
}

#[test]
fn empty_trace_builder_fails_correctly() {
    let mut runner = TestRunner::default();

    runner.run(&Just(()), |_| {
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
            Ok(_) => prop_assert!(false, "Empty trace should not build successfully"),
        }
        Ok(())
    })
    .expect("empty builder property should hold");
}

#[test]
fn trace_builder_respects_max_capacity() {
    let mut runner = TestRunner::default();

    runner.run(&(1..=10_usize), |extra_steps| {
        // Skip this test if MAX_TRACE_STEPS is too large for reasonable testing
        prop_assume!(MAX_TRACE_STEPS <= 100);

        let trace_id = "capacity-test";
        let workflow_name = "max-capacity-preservation";
        let mut builder = TraceBuilder::new(trace_id, workflow_name, demo_env());

        let total_attempts = MAX_TRACE_STEPS + extra_steps;
        let mut recorded_seqs = Vec::new();

        // Add more steps than the maximum capacity
        for i in 0..total_attempts {
            let input = vec![i as u8];
            let output = vec![(i * 2) as u8];
            let timestamp = 1_000_000 + i as u64;

            let seq = builder.record_step(input, output, vec![], timestamp);

            // Sequence numbers should still be assigned correctly
            prop_assert_eq!(seq, i as u64);
            recorded_seqs.push(seq);

            // Step count should cap at MAX_TRACE_STEPS
            let expected_count = std::cmp::min(i + 1, MAX_TRACE_STEPS);
            prop_assert_eq!(builder.step_count(), expected_count);
        }

        // Build the trace
        let (trace, _audit_log) = builder.build()
            .expect("trace should build successfully even when capped");

        // METAMORPHIC PROPERTY: Capped order preservation
        // Should have exactly MAX_TRACE_STEPS, no more
        prop_assert_eq!(trace.steps.len(), MAX_TRACE_STEPS);

        // The recorded steps should be the FIRST MAX_TRACE_STEPS steps
        // (not the last ones - the comment in record_step says it caps, not evicts)
        for (index, step) in trace.steps.iter().enumerate() {
            prop_assert_eq!(
                step.seq,
                index as u64,
                "Capped trace step at index {} has seq {}, expected {}",
                index,
                step.seq,
                index
            );
        }

        // Sequence numbers should still be consecutive from 0
        prop_assert_eq!(trace.steps[0].seq, 0);
        prop_assert_eq!(trace.steps[MAX_TRACE_STEPS - 1].seq, (MAX_TRACE_STEPS - 1) as u64);
        Ok(())
    })
    .expect("max capacity property should hold");
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

        let seq = builder.record_step(
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![],
            2_000_000,
        );

        assert_eq!(seq, 0);
        assert_eq!(builder.step_count(), 1);

        let (trace, _) = builder.build().expect("single step trace should build");
        assert_eq!(trace.steps.len(), 1);
        assert_eq!(trace.steps[0].seq, 0);
    }
}
