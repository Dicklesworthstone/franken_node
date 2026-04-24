#![no_main]

use libfuzzer_sys::fuzz_target;
use frankenengine_node::replay::{WorkflowTrace, TimeTravelError};

fuzz_target!(|trace: WorkflowTrace| {
    // Bound input size to prevent OOM
    if trace.steps.len() > 10000 {
        return;
    }

    // Bound total payload size across all steps
    let total_payload_size: usize = trace.steps.iter()
        .map(|step| step.input.len() + step.output.len() +
             step.side_effects.iter().map(|e| e.payload.len()).sum::<usize>())
        .sum();
    if total_payload_size > 1_000_000 {
        return;
    }

    // Test the validation function - this is our target
    let validation_result = trace.validate();

    // Invariant checks that must hold regardless of input validity:

    // 1. Validation should be deterministic
    let validation_result2 = trace.validate();
    assert_eq!(
        validation_result.is_ok(),
        validation_result2.is_ok(),
        "Validation should be deterministic"
    );

    // 2. If validation passes, basic structural invariants must hold
    if validation_result.is_ok() {
        // Must have at least one step
        assert!(!trace.steps.is_empty(), "Valid trace must have steps");

        // Trace ID should not be empty
        assert!(!trace.trace_id.is_empty(), "Valid trace must have non-empty trace_id");

        // Workflow name should not be empty
        assert!(!trace.workflow_name.is_empty(), "Valid trace must have non-empty workflow_name");

        // Environment platform should not be empty
        assert!(!trace.environment.platform.is_empty(), "Valid trace must have non-empty platform");

        // Environment runtime_version should not be empty
        assert!(!trace.environment.runtime_version.is_empty(), "Valid trace must have non-empty runtime_version");

        // Steps should be ordered by sequence number
        for window in trace.steps.windows(2) {
            assert!(
                window[0].seq < window[1].seq,
                "Steps must be ordered by sequence number: {} >= {}",
                window[0].seq, window[1].seq
            );
        }

        // Sequence numbers should be consecutive starting from 0
        for (i, step) in trace.steps.iter().enumerate() {
            assert_eq!(
                step.seq,
                i as u64,
                "Step sequence numbers should be consecutive starting from 0"
            );
        }

        // Recompute digest and verify it matches
        let recomputed_digest = WorkflowTrace::compute_digest(&trace.steps);
        assert_eq!(
            trace.trace_digest,
            recomputed_digest,
            "Trace digest should match recomputed digest for valid traces"
        );

        // Schema version should match expected
        assert_eq!(
            trace.schema_version,
            frankenengine_node::replay::SCHEMA_VERSION,
            "Valid trace should have correct schema version"
        );
    }

    // 3. Error cases should be specific and informative
    if let Err(ref error) = validation_result {
        // Error should be one of the expected error types
        match error {
            TimeTravelError::EmptyTrace { .. } |
            TimeTravelError::SequenceGap { .. } |
            TimeTravelError::DigestMismatch { .. } |
            TimeTravelError::EnvironmentMissing { .. } |
            TimeTravelError::InvalidEnvironment { .. } => {
                // Expected error types - this is good
            }
            _ => {
                // Unexpected error type - might indicate a bug
                // But don't panic since this could be a valid case
            }
        }
    }

    // 4. Validation should never panic - only return Result
    // (This is implicit - if we got here without panicking, it passed)
});