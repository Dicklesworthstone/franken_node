//! bd-1xbc: Conformance tests for deterministic time-travel capture/replay.
//!
//! Validates that the replay engine produces byte-for-byte equivalent control
//! decisions under the same seed/input, supports stepwise navigation, and
//! provides structured divergence explanations.
#![cfg(feature = "test-support")]

use frankenengine_node::replay::time_travel_engine::{
    build_demo_trace, identity_replay, DivergenceKind, EnvironmentSnapshot, ReplayEngine,
    ReplayVerdict, SideEffect, TraceBuilder, TraceStep, WorkflowTrace,
};
use std::collections::BTreeMap;

fn demo_env() -> EnvironmentSnapshot {
    EnvironmentSnapshot::new(
        1_000_000,
        BTreeMap::from([("FRANKEN_NODE_PROFILE".to_string(), "balanced".to_string())]),
        "linux-x86_64",
        "0.1.0",
    )
}

// ---------------------------------------------------------------------------
// INV-REPLAY-DETERMINISTIC: byte-for-byte equivalent replay
// ---------------------------------------------------------------------------

#[test]
fn identity_replay_produces_identical_verdict() {
    let mut engine = ReplayEngine::new();
    let trace = build_demo_trace("equiv-1", "workflow-alpha", 10);
    engine.register_trace(trace).unwrap();
    let result = engine.replay_identity("equiv-1").unwrap();
    assert_eq!(result.verdict, ReplayVerdict::Identical);
    assert!(result.divergences.is_empty());
    assert_eq!(result.steps_replayed, 10);
}

#[test]
fn two_identical_captures_produce_same_digest() {
    let trace_a = build_demo_trace("det-a", "wf", 5);
    let trace_b = build_demo_trace("det-b", "wf", 5);
    // Same inputs/outputs -> same digest.
    assert_eq!(trace_a.trace_digest, trace_b.trace_digest);
}

#[test]
fn replay_single_step_trace() {
    let mut engine = ReplayEngine::new();
    engine
        .register_trace(build_demo_trace("single", "wf", 1))
        .unwrap();
    let result = engine.replay_identity("single").unwrap();
    assert_eq!(result.verdict, ReplayVerdict::Identical);
    assert_eq!(result.steps_replayed, 1);
}

// ---------------------------------------------------------------------------
// Divergence detection
// ---------------------------------------------------------------------------

#[test]
fn divergent_replay_function_detected() {
    let mut engine = ReplayEngine::new();
    engine
        .register_trace(build_demo_trace("div-test", "wf", 3))
        .unwrap();

    fn bad_replay(
        step: &TraceStep,
        _env: &EnvironmentSnapshot,
    ) -> (Vec<u8>, Vec<SideEffect>) {
        let mut output = step.output.clone();
        output.push(0xFF);
        (output, step.side_effects.clone())
    }

    let result = engine.replay("div-test", bad_replay).unwrap();
    assert_eq!(result.verdict, ReplayVerdict::Diverged(3));
    assert_eq!(result.divergences.len(), 3);
    for div in &result.divergences {
        assert_eq!(div.kind, DivergenceKind::OutputMismatch);
    }
}

#[test]
fn side_effect_divergence_detected() {
    let mut engine = ReplayEngine::new();
    engine
        .register_trace(build_demo_trace("se-div", "wf", 1))
        .unwrap();

    fn bad_effects(
        step: &TraceStep,
        _env: &EnvironmentSnapshot,
    ) -> (Vec<u8>, Vec<SideEffect>) {
        (
            step.output.clone(),
            vec![SideEffect::new("altered", vec![99])],
        )
    }

    let result = engine.replay("se-div", bad_effects).unwrap();
    assert_eq!(result.verdict, ReplayVerdict::Diverged(1));
    assert_eq!(
        result.divergences[0].kind,
        DivergenceKind::SideEffectMismatch
    );
}

// ---------------------------------------------------------------------------
// Trace validation
// ---------------------------------------------------------------------------

#[test]
fn valid_trace_passes_validation() {
    let trace = build_demo_trace("valid", "wf", 5);
    assert!(trace.validate().is_ok());
}

#[test]
fn trace_with_tampered_digest_fails_validation() {
    let mut trace = build_demo_trace("tampered", "wf", 3);
    trace.trace_digest = "0000000000000000".to_string();
    assert!(trace.validate().is_err());
}

// ---------------------------------------------------------------------------
// TraceBuilder
// ---------------------------------------------------------------------------

#[test]
fn trace_builder_produces_valid_trace() {
    let env = demo_env();
    let mut builder = TraceBuilder::new("builder-1", "workflow-builder", env);
    builder.record_step(vec![1, 2], vec![3, 4], vec![], 100);
    builder.record_step(vec![5], vec![6], vec![SideEffect::new("log", vec![7])], 200);
    let (trace, audit) = builder.build().unwrap();
    assert_eq!(trace.steps.len(), 2);
    assert!(trace.validate().is_ok());
    assert!(audit.len() >= 4); // TTR_001, TTR_008, 2x TTR_002, TTR_003, TTR_009
}

// ---------------------------------------------------------------------------
// Engine operations
// ---------------------------------------------------------------------------

#[test]
fn engine_rejects_duplicate_trace() {
    let mut engine = ReplayEngine::new();
    engine
        .register_trace(build_demo_trace("dup", "wf", 1))
        .unwrap();
    let err = engine.register_trace(build_demo_trace("dup", "wf", 1));
    assert!(err.is_err());
}

#[test]
fn engine_remove_trace_works() {
    let mut engine = ReplayEngine::new();
    engine
        .register_trace(build_demo_trace("rm", "wf", 1))
        .unwrap();
    assert!(engine.remove_trace("rm").is_some());
    assert_eq!(engine.trace_count(), 0);
}

#[test]
fn engine_trace_ids_sorted() {
    let mut engine = ReplayEngine::new();
    engine
        .register_trace(build_demo_trace("z", "wf", 1))
        .unwrap();
    engine
        .register_trace(build_demo_trace("a", "wf", 1))
        .unwrap();
    engine
        .register_trace(build_demo_trace("m", "wf", 1))
        .unwrap();
    assert_eq!(engine.trace_ids(), vec!["a", "m", "z"]);
}

// ---------------------------------------------------------------------------
// Serde round-trip
// ---------------------------------------------------------------------------

#[test]
fn workflow_trace_serde_roundtrip() {
    let trace = build_demo_trace("serde", "wf", 3);
    let json = serde_json::to_string(&trace).unwrap();
    let deserialized: WorkflowTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(trace, deserialized);
}
