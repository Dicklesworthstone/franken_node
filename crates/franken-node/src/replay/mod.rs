pub mod time_travel_engine;

#[cfg(test)]
mod replay_conformance_tests;

#[cfg(test)]
mod negative_path_tests {
    use super::time_travel_engine::{
        DivergenceKind, EnvironmentSnapshot, ReplayEngine, ReplayVerdict, SCHEMA_VERSION,
        SideEffect, TimeTravelError, TraceBuilder, TraceStep, WorkflowTrace, build_demo_trace,
    };
    use std::collections::BTreeMap;

    fn valid_environment() -> EnvironmentSnapshot {
        EnvironmentSnapshot::new(42, BTreeMap::new(), "linux-x86_64", "franken-test")
    }

    fn valid_step(seq: u64) -> TraceStep {
        TraceStep::new(
            seq,
            format!("input-{seq}").into_bytes(),
            format!("output-{seq}").into_bytes(),
            Vec::new(),
            seq.saturating_add(1),
        )
    }

    fn valid_trace(trace_id: &str) -> WorkflowTrace {
        let steps = vec![valid_step(0)];
        WorkflowTrace {
            trace_id: trace_id.to_string(),
            workflow_name: "negative-path".to_string(),
            trace_digest: WorkflowTrace::compute_digest(&steps),
            steps,
            environment: valid_environment(),
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }

    fn output_mismatch_replay(
        step: &TraceStep,
        _env: &EnvironmentSnapshot,
    ) -> (Vec<u8>, Vec<SideEffect>) {
        let mut output = step.output.clone();
        output.extend_from_slice(b":changed");
        (output, step.side_effects.clone())
    }

    fn side_effect_mismatch_replay(
        step: &TraceStep,
        _env: &EnvironmentSnapshot,
    ) -> (Vec<u8>, Vec<SideEffect>) {
        (
            step.output.clone(),
            vec![SideEffect::new("changed-effect", b"changed".to_vec())],
        )
    }

    fn full_mismatch_replay(
        step: &TraceStep,
        _env: &EnvironmentSnapshot,
    ) -> (Vec<u8>, Vec<SideEffect>) {
        let mut output = step.output.clone();
        output.extend_from_slice(b":full-change");
        (
            output,
            vec![SideEffect::new("changed-effect", b"changed".to_vec())],
        )
    }

    #[test]
    fn environment_missing_platform_is_rejected() {
        let mut env = valid_environment();
        env.platform.clear();

        let err = env.validate("trace-env-platform").unwrap_err();

        assert!(matches!(
            err,
            TimeTravelError::EnvironmentMissing { field, .. } if field == "platform"
        ));
    }

    #[test]
    fn environment_missing_runtime_version_is_rejected() {
        let mut env = valid_environment();
        env.runtime_version.clear();

        let err = env.validate("trace-env-runtime").unwrap_err();

        assert!(matches!(
            err,
            TimeTravelError::EnvironmentMissing { field, .. } if field == "runtime_version"
        ));
    }

    #[test]
    fn workflow_trace_without_steps_is_rejected() {
        let trace = WorkflowTrace {
            trace_id: "trace-empty".to_string(),
            workflow_name: "empty".to_string(),
            steps: Vec::new(),
            environment: valid_environment(),
            trace_digest: WorkflowTrace::compute_digest(&[]),
            schema_version: SCHEMA_VERSION.to_string(),
        };

        let err = trace.validate().unwrap_err();

        assert!(matches!(err, TimeTravelError::EmptyTrace { .. }));
    }

    #[test]
    fn workflow_trace_sequence_gap_is_rejected() {
        let steps = vec![valid_step(1)];
        let trace = WorkflowTrace {
            trace_id: "trace-gap".to_string(),
            workflow_name: "gap".to_string(),
            trace_digest: WorkflowTrace::compute_digest(&steps),
            steps,
            environment: valid_environment(),
            schema_version: SCHEMA_VERSION.to_string(),
        };

        let err = trace.validate().unwrap_err();

        assert!(matches!(
            err,
            TimeTravelError::SequenceGap {
                expected: 0,
                found: 1,
                ..
            }
        ));
    }

    #[test]
    fn workflow_trace_digest_mismatch_is_rejected() {
        let mut trace = valid_trace("trace-bad-digest");
        trace.trace_digest = "sha256:not-the-real-digest".to_string();

        let err = trace.validate().unwrap_err();

        assert!(matches!(err, TimeTravelError::DigestMismatch { .. }));
    }

    #[test]
    fn trace_builder_without_steps_fails_to_build() {
        let builder = TraceBuilder::new("trace-builder-empty", "empty", valid_environment());

        let err = builder.build().unwrap_err();

        assert!(matches!(err, TimeTravelError::EmptyTrace { .. }));
    }

    #[test]
    fn replay_engine_rejects_duplicate_trace_registration() {
        let mut engine = ReplayEngine::new();
        let trace = valid_trace("trace-duplicate");
        engine
            .register_trace(trace.clone())
            .expect("first registration should succeed");

        let err = engine.register_trace(trace).unwrap_err();

        assert!(matches!(err, TimeTravelError::DuplicateTrace { .. }));
        assert_eq!(engine.trace_count(), 1);
    }

    #[test]
    fn replay_missing_trace_is_rejected_without_audit_growth() {
        let mut engine = ReplayEngine::new();

        let err = engine.replay_identity("trace-missing").unwrap_err();

        assert!(matches!(err, TimeTravelError::TraceNotFound { .. }));
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn workflow_trace_duplicate_sequence_is_rejected() {
        let steps = vec![valid_step(0), valid_step(0)];
        let trace = WorkflowTrace {
            trace_id: "trace-duplicate-seq".to_string(),
            workflow_name: "duplicate-seq".to_string(),
            trace_digest: WorkflowTrace::compute_digest(&steps),
            steps,
            environment: valid_environment(),
            schema_version: SCHEMA_VERSION.to_string(),
        };

        let err = trace.validate().unwrap_err();

        assert!(matches!(
            err,
            TimeTravelError::SequenceGap {
                expected: 1,
                found: 0,
                ..
            }
        ));
    }

    #[test]
    fn workflow_trace_missing_environment_is_rejected_during_trace_validation() {
        let mut trace = valid_trace("trace-env-missing");
        trace.environment.platform.clear();

        let err = trace.validate().unwrap_err();

        assert!(matches!(
            err,
            TimeTravelError::EnvironmentMissing { field, .. } if field == "platform"
        ));
    }

    #[test]
    fn trace_builder_with_invalid_environment_fails_at_build() {
        let mut env = valid_environment();
        env.runtime_version.clear();
        let mut builder = TraceBuilder::new("trace-builder-bad-env", "bad-env", env);
        builder.record_step(b"input".to_vec(), b"output".to_vec(), Vec::new(), 1);

        let err = builder.build().unwrap_err();

        assert!(matches!(
            err,
            TimeTravelError::EnvironmentMissing { field, .. } if field == "runtime_version"
        ));
    }

    #[test]
    fn register_trace_rejects_digest_tampering_without_storing_trace() {
        let mut engine = ReplayEngine::new();
        let mut trace = valid_trace("trace-register-bad-digest");
        trace.trace_digest = "sha256:tampered".to_string();

        let err = engine.register_trace(trace).unwrap_err();

        assert!(matches!(err, TimeTravelError::DigestMismatch { .. }));
        assert_eq!(engine.trace_count(), 0);
    }

    #[test]
    fn register_trace_rejects_missing_environment_without_storing_trace() {
        let mut engine = ReplayEngine::new();
        let mut trace = valid_trace("trace-register-bad-env");
        trace.environment.runtime_version.clear();

        let err = engine.register_trace(trace).unwrap_err();

        assert!(matches!(err, TimeTravelError::EnvironmentMissing { .. }));
        assert_eq!(engine.trace_count(), 0);
    }

    #[test]
    fn removed_trace_cannot_be_replayed() {
        let mut engine = ReplayEngine::new();
        let trace = valid_trace("trace-remove-then-replay");
        engine
            .register_trace(trace)
            .expect("fixture trace should register");
        let removed = engine.remove_trace("trace-remove-then-replay");

        let err = engine
            .replay_identity("trace-remove-then-replay")
            .unwrap_err();

        assert!(removed.is_some());
        assert!(matches!(err, TimeTravelError::TraceNotFound { .. }));
    }

    #[test]
    fn zero_step_demo_trace_is_invalid() {
        let trace = build_demo_trace("trace-zero-demo", "zero-demo", 0);

        let err = trace.validate().unwrap_err();

        assert!(matches!(err, TimeTravelError::EmptyTrace { .. }));
    }

    #[test]
    fn replay_output_mismatch_records_divergence_verdict() {
        let mut engine = ReplayEngine::new();
        engine
            .register_trace(valid_trace("trace-output-divergence"))
            .expect("fixture trace should register");

        let result = engine
            .replay("trace-output-divergence", output_mismatch_replay)
            .expect("replay should report divergence");

        assert!(matches!(&result.verdict, ReplayVerdict::Diverged(1)));
        assert_eq!(result.divergences[0].kind, DivergenceKind::OutputMismatch);
        assert_eq!(result.divergences[0].step_seq, 0);
    }

    #[test]
    fn workflow_trace_digest_rejects_input_tampering() {
        let mut trace = valid_trace("trace-input-tamper");
        trace.steps[0].input = b"tampered-input".to_vec();

        let err = trace.validate().unwrap_err();

        assert!(matches!(
            err,
            TimeTravelError::DigestMismatch { ref trace_id, .. }
                if trace_id == "trace-input-tamper"
        ));
    }

    #[test]
    fn workflow_trace_digest_rejects_side_effect_payload_tampering() {
        let steps = vec![TraceStep::new(
            0,
            b"input".to_vec(),
            b"output".to_vec(),
            vec![SideEffect::new("log", b"before".to_vec())],
            1,
        )];
        let mut trace = WorkflowTrace {
            trace_id: "trace-effect-tamper".to_string(),
            workflow_name: "effect-tamper".to_string(),
            trace_digest: WorkflowTrace::compute_digest(&steps),
            steps,
            environment: valid_environment(),
            schema_version: SCHEMA_VERSION.to_string(),
        };
        trace.steps[0].side_effects = vec![SideEffect::new("log", b"after".to_vec())];

        let err = trace.validate().unwrap_err();

        assert!(matches!(
            err,
            TimeTravelError::DigestMismatch { ref trace_id, .. }
                if trace_id == "trace-effect-tamper"
        ));
    }

    #[test]
    fn replay_side_effect_mismatch_records_side_effect_divergence() {
        let mut engine = ReplayEngine::new();
        let steps = vec![TraceStep::new(
            0,
            b"input".to_vec(),
            b"output".to_vec(),
            vec![SideEffect::new("log", b"captured".to_vec())],
            1,
        )];
        let trace = WorkflowTrace {
            trace_id: "trace-side-effect-divergence".to_string(),
            workflow_name: "side-effect-divergence".to_string(),
            trace_digest: WorkflowTrace::compute_digest(&steps),
            steps,
            environment: valid_environment(),
            schema_version: SCHEMA_VERSION.to_string(),
        };
        engine
            .register_trace(trace)
            .expect("fixture trace should register");

        let result = engine
            .replay("trace-side-effect-divergence", side_effect_mismatch_replay)
            .expect("replay should report side-effect divergence");

        assert!(matches!(&result.verdict, ReplayVerdict::Diverged(1)));
        assert_eq!(
            result.divergences[0].kind,
            DivergenceKind::SideEffectMismatch
        );
        assert!(
            result.divergences[0]
                .explanation
                .contains("effects_match=false")
        );
    }

    #[test]
    fn replay_full_mismatch_records_full_divergence() {
        let mut engine = ReplayEngine::new();
        engine
            .register_trace(valid_trace("trace-full-divergence"))
            .expect("fixture trace should register");

        let result = engine
            .replay("trace-full-divergence", full_mismatch_replay)
            .expect("replay should report full divergence");

        assert!(matches!(&result.verdict, ReplayVerdict::Diverged(1)));
        assert_eq!(result.divergences[0].kind, DivergenceKind::FullMismatch);
        assert!(
            result.divergences[0]
                .explanation
                .contains("output_match=false")
        );
        assert!(
            result.divergences[0]
                .explanation
                .contains("effects_match=false")
        );
    }

    #[test]
    fn replay_divergence_audit_records_start_diverge_and_completion() {
        let mut engine = ReplayEngine::new();
        engine
            .register_trace(valid_trace("trace-divergence-audit"))
            .expect("fixture trace should register");

        let _result = engine
            .replay("trace-divergence-audit", full_mismatch_replay)
            .expect("replay should complete with divergence");

        assert!(
            engine
                .audit_log()
                .iter()
                .any(|entry| entry.event_code == "TTR-004")
        );
        assert!(
            engine
                .audit_log()
                .iter()
                .any(|entry| entry.event_code == "TTR-006")
        );
        assert!(
            engine
                .audit_log()
                .iter()
                .any(|entry| entry.event_code == "TTR-007")
        );
    }

    #[test]
    fn divergence_kind_deserialize_rejects_camel_case_wire_value() {
        let result = serde_json::from_str::<DivergenceKind>("\"OutputMismatch\"");

        assert!(result.is_err());
    }

    #[test]
    fn environment_snapshot_deserialize_rejects_string_clock_seed() {
        let result = serde_json::from_value::<EnvironmentSnapshot>(serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "clock_seed_ns": "42",
            "env_vars": {},
            "platform": "linux-x86_64",
            "runtime_version": "franken-test"
        }));

        assert!(result.is_err());
    }

    #[test]
    fn workflow_trace_deserialize_rejects_non_array_steps() {
        let result = serde_json::from_value::<WorkflowTrace>(serde_json::json!({
            "trace_id": "trace-bad-wire",
            "workflow_name": "bad-wire",
            "steps": {},
            "environment": {
                "schema_version": SCHEMA_VERSION,
                "clock_seed_ns": 42,
                "env_vars": {},
                "platform": "linux-x86_64",
                "runtime_version": "franken-test"
            },
            "trace_digest": "sha256:unused",
            "schema_version": SCHEMA_VERSION
        }));

        assert!(result.is_err());
    }
}
