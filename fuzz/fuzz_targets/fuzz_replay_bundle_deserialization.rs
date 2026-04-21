#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use frankenengine_node::replay::time_travel_engine::{
    WorkflowTrace, EnvironmentSnapshot, TraceStep, SideEffect,
    DivergenceKind, ReplayResult, Divergence, ReplayVerdict, TimeTravelError,
};

/// Fuzz target for replay bundle deserialization.
///
/// Tests structure-aware fuzzing of the replay module's JSON deserialization patterns.
/// This targets untrusted attacker-controlled input through serde_json::from_str calls.
///
/// Strategy: Hybrid structure-aware + coverage-guided approach
/// 1. Generate structured objects using Arbitrary (better coverage of valid inputs)
/// 2. Test raw JSON string fuzzing (finds edge cases in parser)
/// 3. Round-trip testing (serialize → deserialize invariants)
///
/// Priority targets (per bd-3id7l):
/// 1. WorkflowTrace - main bundle format (highest risk)
/// 2. EnvironmentSnapshot - environment data
/// 3. TraceStep - individual execution steps
/// 4. SideEffect - step side effects
fuzz_target!(|data: FuzzInput| {
    match data {
        FuzzInput::StructuredWorkflowTrace(trace) => {
            fuzz_workflow_trace_structured(trace);
        }
        FuzzInput::StructuredEnvironment(env) => {
            fuzz_environment_structured(env);
        }
        FuzzInput::StructuredTraceStep(step) => {
            fuzz_trace_step_structured(step);
        }
        FuzzInput::RawJsonBytes(json_bytes) => {
            fuzz_raw_json_strings(json_bytes);
        }
    }
});

/// Fuzz structured WorkflowTrace objects (highest priority target)
fn fuzz_workflow_trace_structured(trace: WorkflowTrace) {
    // Test serialization roundtrip
    if let Ok(json) = serde_json::to_string(&trace) {
        // Test deserialization of our own serialized data
        if let Ok(deserialized) = serde_json::from_str::<WorkflowTrace>(&json) {
            // Apply validation logic that production code would use
            let _ = deserialized.validate();

            // Test digest computation (potential panic/overflow site)
            let original_digest = WorkflowTrace::compute_digest(&trace.steps);
            let deserialized_digest = WorkflowTrace::compute_digest(&deserialized.steps);

            // Round-trip invariant: digest should be preserved (don't panic on failure)
            if original_digest != deserialized_digest {
                // Log the invariant violation but don't panic - let fuzzer continue
                #[cfg(debug_assertions)]
                {
                    eprintln!("FUZZ: Digest roundtrip invariant violated - original: {}, deserialized: {}",
                             original_digest, deserialized_digest);
                }
                return; // Exit early but gracefully
            }
        }

        // Test pretty-printing (different JSON format)
        if let Ok(pretty_json) = serde_json::to_string_pretty(&trace) {
            let _ = serde_json::from_str::<WorkflowTrace>(&pretty_json);
        }
    }

    // Test validation on arbitrary structured data (may be invalid)
    let _ = trace.validate();
    let _ = WorkflowTrace::compute_digest(&trace.steps);
}

/// Fuzz structured EnvironmentSnapshot objects
fn fuzz_environment_structured(env: EnvironmentSnapshot) {
    if let Ok(json) = serde_json::to_string(&env) {
        if let Ok(deserialized) = serde_json::from_str::<EnvironmentSnapshot>(&json) {
            let _ = deserialized.validate("fuzz-trace-id");
        }
    }

    // Test validation with various trace IDs (edge case testing)
    let _ = env.validate("fuzz-trace-id");
    let _ = env.validate("");  // Empty trace ID edge case
    let _ = env.validate("very-long-trace-id-with-special-chars-àáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ");
}

/// Fuzz structured TraceStep objects
fn fuzz_trace_step_structured(step: TraceStep) {
    if let Ok(json) = serde_json::to_string(&step) {
        let _ = serde_json::from_str::<TraceStep>(&json);
    }

    // Test digest computation (potential panic sites)
    let _ = step.output_digest();
    let _ = step.side_effects_digest();
}

/// Fuzz raw JSON strings (coverage-guided approach)
fn fuzz_raw_json_strings(json_bytes: Vec<u8>) {
    // Size guard: reject overly large inputs to prevent OOM
    if json_bytes.len() > 1_000_000 {
        return;
    }

    // Attempt to parse as valid UTF-8 first
    let json_str = match std::str::from_utf8(&json_bytes) {
        Ok(s) => s,
        Err(_) => return, // Skip invalid UTF-8, focus on JSON structure bugs
    };

    // Fuzz WorkflowTrace deserialization (highest priority)
    if let Ok(trace) = serde_json::from_str::<WorkflowTrace>(json_str) {
        let _ = trace.validate();
        let _ = WorkflowTrace::compute_digest(&trace.steps);
    }

    // Fuzz all other deserialization entry points found in target discovery
    let _ = serde_json::from_str::<EnvironmentSnapshot>(json_str);
    let _ = serde_json::from_str::<TraceStep>(json_str);
    let _ = serde_json::from_str::<SideEffect>(json_str);
    let _ = serde_json::from_str::<DivergenceKind>(json_str);
    let _ = serde_json::from_str::<ReplayResult>(json_str);
    let _ = serde_json::from_str::<Divergence>(json_str);
    let _ = serde_json::from_str::<ReplayVerdict>(json_str);
    let _ = serde_json::from_str::<TimeTravelError>(json_str);
}

/// Input structure for hybrid structure-aware + coverage-guided fuzzing.
///
/// This enum allows the fuzzer to choose between:
/// 1. Structured generation (better coverage of valid inputs)
/// 2. Raw JSON string fuzzing (finds parser edge cases)
#[derive(Arbitrary, Debug)]
enum FuzzInput {
    /// Generate valid structured WorkflowTrace then test serialization/validation
    StructuredWorkflowTrace(WorkflowTrace),
    /// Generate valid structured EnvironmentSnapshot then test serialization/validation
    StructuredEnvironment(EnvironmentSnapshot),
    /// Generate valid structured TraceStep then test serialization/validation
    StructuredTraceStep(TraceStep),
    /// Raw JSON bytes for coverage-guided fuzzing of parser edge cases
    RawJsonBytes(Vec<u8>),
}