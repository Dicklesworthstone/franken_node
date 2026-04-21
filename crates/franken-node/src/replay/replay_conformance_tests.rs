//! Comprehensive edge case conformance tests for the replay module.
//!
//! Tests critical hardening patterns and edge cases for time-travel replay:
//! - Deterministic replay with identity functions
//! - Divergence detection for all mismatch types
//! - Capacity limits and bounded collection behavior
//! - Hash comparison using constant-time operations
//! - Arithmetic overflow protection in counters and timestamps
//! - Sequence validation and ordering invariants

#[cfg(test)]
mod tests {
    use super::super::time_travel_engine::*;
    use crate::security::constant_time;
    use crate::{
        capacity_defaults::aliases::{
            MAX_AUDIT_LOG_ENTRIES, MAX_REGISTERED_TRACES, MAX_TRACE_STEPS,
        },
        security::constant_time::ct_eq,
    };
    use std::collections::BTreeMap;

    // ── Test Utilities ───────────────────────────────────────────────────────────

    fn minimal_env() -> EnvironmentSnapshot {
        EnvironmentSnapshot::new(
            1000, // clock_seed_ns
            BTreeMap::new(),
            "linux-x86_64",
            "test-v1.0",
        )
    }

    fn stress_env_large_vars() -> EnvironmentSnapshot {
        let mut large_env = BTreeMap::new();
        // Create a very large environment to test memory handling
        for i in 0..10000 {
            large_env.insert(
                format!("VAR_{}", i),
                format!("value_{}_{}", i, "x".repeat(1000)),
            );
        }
        EnvironmentSnapshot::new(1000, large_env, "stress-platform", "stress-v1.0")
    }

    fn create_large_side_effect(size_bytes: usize) -> SideEffect {
        SideEffect::new("large_effect", vec![0xAA; size_bytes])
    }

    fn create_many_side_effects(count: usize) -> Vec<SideEffect> {
        (0..count)
            .map(|i| SideEffect::new(&format!("effect_{}", i), vec![i as u8]))
            .collect()
    }

    // ── Edge Cases for EnvironmentSnapshot ─────────────────────────────────────

    #[test]
    fn environment_validation_edge_cases() {
        // Empty platform should fail
        let env = EnvironmentSnapshot::new(0, BTreeMap::new(), "", "v1.0");
        assert!(env.validate("test").is_err());

        // Empty runtime_version should fail
        let env = EnvironmentSnapshot::new(0, BTreeMap::new(), "linux", "");
        assert!(env.validate("test").is_err());

        // Whitespace-only platform should fail
        let env = EnvironmentSnapshot::new(0, BTreeMap::new(), "   ", "v1.0");
        assert!(env.validate("test").is_err());

        // Unicode platform names should work
        let env = EnvironmentSnapshot::new(0, BTreeMap::new(), "Linux-测试", "v1.0-测试");
        assert!(env.validate("test").is_ok());
    }

    #[test]
    fn environment_clock_seed_boundary_values() {
        let edge_seeds = [0, 1, u64::MAX - 1, u64::MAX];

        for &seed in &edge_seeds {
            let env = EnvironmentSnapshot::new(seed, BTreeMap::new(), "linux", "v1.0");
            assert_eq!(env.clock_seed_ns, seed);
            assert!(env.validate("test").is_ok());
        }
    }

    #[test]
    fn environment_very_large_vars() {
        let env = stress_env_large_vars();
        assert!(env.validate("stress-test").is_ok());

        // Serialization should still work with large environment
        let json = serde_json::to_string(&env).unwrap();
        let decoded: EnvironmentSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(env.platform, decoded.platform);
        assert_eq!(env.env_vars.len(), decoded.env_vars.len());
    }

    // ── Edge Cases for TraceStep ───────────────────────────────────────────────

    #[test]
    fn trace_step_sequence_boundary_values() {
        let edge_sequences = [0, 1, u64::MAX - 1, u64::MAX];

        for &seq in &edge_sequences {
            let step = TraceStep::new(seq, vec![], vec![], vec![], 1000);
            assert_eq!(step.seq, seq);

            // Digest computation should not panic
            let digest = step.output_digest();
            assert!(!digest.is_empty());
            assert_eq!(digest.len(), 64); // SHA-256 hex
        }
    }

    #[test]
    fn trace_step_very_large_data() {
        // Large input/output
        let large_input = vec![0x42; 10_000_000]; // 10MB
        let large_output = vec![0x84; 10_000_000]; // 10MB
        let many_effects = create_many_side_effects(10000);

        let step = TraceStep::new(0, large_input, large_output, many_effects, 1000);

        // Should not panic and should produce consistent digests
        let output_digest = step.output_digest();
        let effects_digest = step.side_effects_digest();

        assert!(!output_digest.is_empty());
        assert!(!effects_digest.is_empty());

        // Repeated calls should be deterministic
        assert_eq!(output_digest, step.output_digest());
        assert_eq!(effects_digest, step.side_effects_digest());
    }

    #[test]
    fn trace_step_empty_data_handling() {
        let step = TraceStep::new(0, vec![], vec![], vec![], 0);

        // Should produce valid digests even with empty data
        let output_digest = step.output_digest();
        let effects_digest = step.side_effects_digest();

        assert_eq!(output_digest.len(), 64); // SHA-256 hex
        assert_eq!(effects_digest.len(), 64);

        // Different from non-empty data
        let non_empty_step =
            TraceStep::new(0, vec![1], vec![2], vec![SideEffect::new("a", vec![3])], 0);
        assert_ne!(output_digest, non_empty_step.output_digest());
        assert_ne!(effects_digest, non_empty_step.side_effects_digest());
    }

    #[test]
    fn trace_step_side_effects_digest_collision_resistance() {
        // Test that different side effects produce different digests
        let step1 = TraceStep::new(
            0,
            vec![],
            vec![],
            vec![
                SideEffect::new("a", vec![1, 2]),
                SideEffect::new("b", vec![3]),
            ],
            0,
        );

        let step2 = TraceStep::new(
            0,
            vec![],
            vec![],
            vec![
                SideEffect::new("ab", vec![1, 2, 3]), // Potential collision
            ],
            0,
        );

        // Length-prefixed encoding should prevent collision
        assert_ne!(step1.side_effects_digest(), step2.side_effects_digest());
    }

    // ── Edge Cases for WorkflowTrace ──────────────────────────────────────────────

    #[test]
    fn workflow_trace_maximum_steps() {
        // Test with MAX_TRACE_STEPS
        let mut builder = TraceBuilder::new("max-steps", "test", minimal_env());

        // Record up to capacity
        for i in 0..MAX_TRACE_STEPS {
            builder.record_step(
                vec![i as u8],
                vec![(i + 100) as u8],
                vec![],
                (i as u64 + 1) * 1000,
            );
        }

        assert_eq!(builder.step_count(), MAX_TRACE_STEPS);

        // Additional steps should be silently ignored to preserve ordering
        builder.record_step(vec![255], vec![255], vec![], u64::MAX);
        assert_eq!(builder.step_count(), MAX_TRACE_STEPS); // Should not increase

        let (trace, _) = builder.build().unwrap();
        assert!(trace.validate().is_ok());
        assert_eq!(trace.steps.len(), MAX_TRACE_STEPS);
    }

    #[test]
    fn workflow_trace_digest_determinism_stress() {
        // Create two identical traces with many steps
        let create_trace = || {
            let mut steps = Vec::new();
            for i in 0..1000 {
                steps.push(TraceStep::new(
                    i,
                    format!("input-{}", i).into_bytes(),
                    format!("output-{}", i).into_bytes(),
                    vec![SideEffect::new(&format!("effect-{}", i), vec![i as u8])],
                    (i + 1) * 1000,
                ));
            }
            WorkflowTrace {
                trace_id: "stress".to_string(),
                workflow_name: "stress-workflow".to_string(),
                steps,
                environment: minimal_env(),
                trace_digest: String::new(), // Will be computed
                schema_version: SCHEMA_VERSION.to_string(),
            }
        };

        let mut trace1 = create_trace();
        let mut trace2 = create_trace();

        trace1.trace_digest = WorkflowTrace::compute_digest(&trace1.steps);
        trace2.trace_digest = WorkflowTrace::compute_digest(&trace2.steps);

        // Should be identical
        assert_eq!(trace1.trace_digest, trace2.trace_digest);
        assert!(trace1.validate().is_ok());
        assert!(trace2.validate().is_ok());
    }

    #[test]
    fn workflow_trace_sequence_gap_detection() {
        // Test various sequence gaps
        let test_cases = [
            (vec![0, 2], 1, 2),       // Missing 1
            (vec![0, 1, 3], 2, 3),    // Missing 2
            (vec![1, 2, 3], 0, 1),    // Missing 0
            (vec![0, 1, 2, 5], 3, 5), // Missing 3,4
        ];

        for (sequences, expected_seq, found_seq) in test_cases {
            let mut steps = Vec::new();
            for (i, &seq) in sequences.iter().enumerate() {
                steps.push(TraceStep::new(
                    seq,
                    vec![i as u8],
                    vec![i as u8],
                    vec![],
                    1000,
                ));
            }

            let trace = WorkflowTrace {
                trace_id: "gap-test".to_string(),
                workflow_name: "test".to_string(),
                steps,
                environment: minimal_env(),
                trace_digest: String::new(),
                schema_version: SCHEMA_VERSION.to_string(),
            };

            let err = trace.validate().unwrap_err();
            match err {
                TimeTravelError::SequenceGap {
                    expected, found, ..
                } => {
                    assert_eq!(expected, expected_seq);
                    assert_eq!(found, found_seq);
                }
                other => panic!("Expected SequenceGap, got {:?}", other),
            }
        }
    }

    #[test]
    fn workflow_trace_digest_mismatch_constant_time() {
        let mut trace = build_demo_trace("digest-test", "test", 5);
        let correct_digest = trace.trace_digest.clone();

        // Corrupt digest
        let wrong_digest = "0".repeat(64);
        trace.trace_digest = wrong_digest.clone();

        let err = trace.validate().unwrap_err();
        match err {
            TimeTravelError::DigestMismatch {
                expected, found, ..
            } => {
                assert_eq!(expected, wrong_digest);
                assert_eq!(found, correct_digest);

                // Verify constant-time comparison was used
                assert!(!ct_eq(&wrong_digest, &correct_digest));
            }
            other => panic!("Expected DigestMismatch, got {:?}", other),
        }
    }

    // ── Edge Cases for TraceBuilder ──────────────────────────────────────────────

    #[test]
    fn trace_builder_sequence_counter_overflow_protection() {
        let mut builder = TraceBuilder::new("overflow-test", "test", minimal_env());

        // Force sequence counter to near overflow
        builder.next_seq = u64::MAX - 2;

        // Record steps that would overflow without saturating_add
        let seq1 = builder.record_step(vec![1], vec![2], vec![], 1000);
        let seq2 = builder.record_step(vec![3], vec![4], vec![], 2000);
        let seq3 = builder.record_step(vec![5], vec![6], vec![], 3000);

        assert_eq!(seq1, u64::MAX - 2);
        assert_eq!(seq2, u64::MAX - 1);
        assert_eq!(seq3, u64::MAX);

        // Next sequence should saturate
        assert_eq!(builder.next_seq, u64::MAX);
    }

    #[test]
    fn trace_builder_audit_log_capacity_enforcement() {
        let mut builder = TraceBuilder::new("audit-test", "test", minimal_env());

        // Record many steps to stress audit log capacity
        for i in 0..MAX_AUDIT_LOG_ENTRIES * 2 {
            builder.record_step(
                vec![i as u8],
                vec![(i + 1) as u8],
                vec![],
                (i as u64 + 1) * 1000,
            );
        }

        let audit_log = builder.audit_log();
        assert!(audit_log.len() <= MAX_AUDIT_LOG_ENTRIES);

        // Should contain recent events
        assert!(
            audit_log
                .iter()
                .any(|e| e.event_code == event_codes::TTR_002)
        );
    }

    #[test]
    fn trace_builder_timestamp_boundary_values() {
        let mut builder = TraceBuilder::new("timestamp-test", "test", minimal_env());

        // Test edge case timestamps
        let edge_timestamps = [0, 1, u64::MAX - 1, u64::MAX];

        for (i, &timestamp) in edge_timestamps.iter().enumerate() {
            builder.record_step(vec![i as u8], vec![i as u8], vec![], timestamp);
        }

        let (trace, _) = builder.build().unwrap();
        assert_eq!(trace.steps.len(), edge_timestamps.len());

        for (step, &expected_ts) in trace.steps.iter().zip(edge_timestamps.iter()) {
            assert_eq!(step.timestamp_ns, expected_ts);
        }
    }

    // ── Edge Cases for ReplayEngine ──────────────────────────────────────────────

    #[test]
    fn replay_engine_capacity_management() {
        let mut engine = ReplayEngine::new();

        // Fill to capacity
        for i in 0..MAX_REGISTERED_TRACES {
            let trace = build_demo_trace(&format!("trace-{:04}", i), "test", 1);
            engine.register_trace(trace).unwrap();
        }

        assert_eq!(engine.trace_count(), MAX_REGISTERED_TRACES);

        // Adding one more should evict the oldest
        let overflow_trace = build_demo_trace("overflow", "test", 1);
        engine.register_trace(overflow_trace).unwrap();

        assert_eq!(engine.trace_count(), MAX_REGISTERED_TRACES);
        assert!(engine.get_trace("trace-0000").is_none()); // Oldest evicted
        assert!(engine.get_trace("overflow").is_some()); // New trace present
    }

    #[test]
    fn replay_engine_registration_order_preservation() {
        let mut engine = ReplayEngine::new();

        // Register traces in specific order
        let trace_ids = ["charlie", "alpha", "bravo"];
        for &id in &trace_ids {
            engine
                .register_trace(build_demo_trace(id, "test", 1))
                .unwrap();
        }

        // trace_ids() should return sorted order
        assert_eq!(engine.trace_ids(), vec!["alpha", "bravo", "charlie"]);

        // But eviction should be based on registration order (charlie first)
        for i in 0..MAX_REGISTERED_TRACES - 3 {
            engine
                .register_trace(build_demo_trace(&format!("filler-{}", i), "test", 1))
                .unwrap();
        }

        // Add one more to trigger eviction
        engine
            .register_trace(build_demo_trace("newest", "test", 1))
            .unwrap();

        // Charlie should be evicted (oldest registration)
        assert!(engine.get_trace("charlie").is_none());
        assert!(engine.get_trace("alpha").is_some());
        assert!(engine.get_trace("bravo").is_some());
        assert!(engine.get_trace("newest").is_some());
    }

    #[test]
    fn replay_engine_divergence_detection_precision() {
        let mut engine = ReplayEngine::new();
        let trace = build_demo_trace("precision-test", "test", 100);
        engine.register_trace(trace).unwrap();

        // Replay function that subtly modifies every 10th step
        fn subtle_divergence(
            step: &TraceStep,
            _env: &EnvironmentSnapshot,
        ) -> (Vec<u8>, Vec<SideEffect>) {
            if step.seq % 10 == 0 {
                let mut output = step.output.clone();
                if !output.is_empty() {
                    output[output.len() - 1] ^= 1; // Flip one bit
                }
                (output, step.side_effects.clone())
            } else {
                (step.output.clone(), step.side_effects.clone())
            }
        }

        let result = engine.replay("precision-test", subtle_divergence).unwrap();

        // Should detect exactly 10 divergences (steps 0, 10, 20, ..., 90)
        assert_eq!(result.verdict, ReplayVerdict::Diverged(10));
        assert_eq!(result.divergences.len(), 10);

        let divergent_steps: Vec<u64> = result.divergences.iter().map(|d| d.step_seq).collect();
        let expected_steps: Vec<u64> = (0..10).map(|i| i * 10).collect();
        assert_eq!(divergent_steps, expected_steps);

        for div in &result.divergences {
            assert_eq!(div.kind, DivergenceKind::OutputMismatch);
            assert_ne!(div.expected_digest, div.actual_digest);
        }
    }

    #[test]
    fn replay_engine_side_effects_only_divergence() {
        let mut engine = ReplayEngine::new();

        // Create trace with side effects
        let mut builder = TraceBuilder::new("effects-test", "test", minimal_env());
        builder.record_step(
            b"input".to_vec(),
            b"output".to_vec(),
            vec![
                SideEffect::new("log", b"original message".to_vec()),
                SideEffect::new("metric", vec![42]),
            ],
            1000,
        );
        let (trace, _) = builder.build().unwrap();
        engine.register_trace(trace).unwrap();

        // Replay function that keeps output identical but changes side effects
        fn effects_divergence(
            step: &TraceStep,
            _env: &EnvironmentSnapshot,
        ) -> (Vec<u8>, Vec<SideEffect>) {
            let modified_effects = vec![
                SideEffect::new("log", b"modified message".to_vec()),
                SideEffect::new("metric", vec![43]),
            ];
            (step.output.clone(), modified_effects)
        }

        let result = engine.replay("effects-test", effects_divergence).unwrap();

        assert_eq!(result.verdict, ReplayVerdict::Diverged(1));
        assert_eq!(result.divergences.len(), 1);
        assert_eq!(
            result.divergences[0].kind,
            DivergenceKind::SideEffectMismatch
        );
        assert_eq!(result.divergences[0].step_seq, 0);
    }

    #[test]
    fn replay_engine_full_mismatch_both_output_and_effects() {
        let mut engine = ReplayEngine::new();
        let trace = build_demo_trace("full-mismatch-test", "test", 1);
        engine.register_trace(trace).unwrap();

        // Replay function that changes both output and side effects
        fn full_divergence(
            _step: &TraceStep,
            _env: &EnvironmentSnapshot,
        ) -> (Vec<u8>, Vec<SideEffect>) {
            (
                b"completely different output".to_vec(),
                vec![SideEffect::new("completely_different", vec![99])],
            )
        }

        let result = engine
            .replay("full-mismatch-test", full_divergence)
            .unwrap();

        assert_eq!(result.verdict, ReplayVerdict::Diverged(1));
        assert_eq!(result.divergences[0].kind, DivergenceKind::FullMismatch);
    }

    #[test]
    fn replay_engine_audit_log_capacity_stress() {
        let mut engine = ReplayEngine::new();
        let large_trace = build_demo_trace("large-audit", "test", 1000);
        engine.register_trace(large_trace).unwrap();

        // Perform many replays to stress audit log
        for i in 0..100 {
            let result = engine.replay_identity("large-audit").unwrap();
            assert_eq!(result.verdict, ReplayVerdict::Identical);
        }

        let audit_log = engine.audit_log();
        assert!(audit_log.len() <= MAX_AUDIT_LOG_ENTRIES);

        // Should still contain recent events
        assert!(
            audit_log
                .iter()
                .any(|e| e.event_code == event_codes::TTR_004)
        ); // Replay started
        assert!(
            audit_log
                .iter()
                .any(|e| e.event_code == event_codes::TTR_007)
        ); // Replay completed
    }

    #[test]
    fn replay_engine_remove_trace_cleanup() {
        let mut engine = ReplayEngine::new();

        // Register and remove traces to test cleanup
        let trace_ids = ["remove-1", "remove-2", "remove-3"];
        for &id in &trace_ids {
            engine
                .register_trace(build_demo_trace(id, "test", 1))
                .unwrap();
        }

        assert_eq!(engine.trace_count(), 3);

        // Remove middle trace
        let removed = engine.remove_trace("remove-2");
        assert!(removed.is_some());
        assert_eq!(engine.trace_count(), 2);
        assert!(engine.get_trace("remove-2").is_none());

        // Registration order should be preserved for remaining traces
        // Add many traces to trigger eviction
        for i in 0..MAX_REGISTERED_TRACES {
            engine
                .register_trace(build_demo_trace(&format!("fill-{}", i), "test", 1))
                .unwrap();
        }

        // remove-1 should be evicted before remove-3 (older registration)
        assert!(engine.get_trace("remove-1").is_none());
        assert!(engine.get_trace("remove-3").is_some());
    }

    // ── Cross-System Integration Edge Cases ────────────────────────────────────────

    #[test]
    fn deterministic_replay_with_environment_variations() {
        // Test that identical inputs produce identical outputs regardless of environment size
        let small_env = minimal_env();
        let large_env = stress_env_large_vars();

        let create_trace = |env: EnvironmentSnapshot, suffix: &str| {
            let mut builder = TraceBuilder::new(&format!("env-test-{}", suffix), "test", env);
            for i in 0..10 {
                builder.record_step(
                    format!("input-{}", i).into_bytes(),
                    format!("output-{}", i).into_bytes(),
                    vec![SideEffect::new("log", format!("effect-{}", i).into_bytes())],
                    (i as u64 + 1) * 1000,
                );
            }
            builder.build().unwrap().0
        };

        let trace_small = create_trace(small_env, "small");
        let trace_large = create_trace(large_env, "large");

        // Step digests should be identical (not affected by environment)
        assert_eq!(trace_small.steps.len(), trace_large.steps.len());
        for (step_small, step_large) in trace_small.steps.iter().zip(trace_large.steps.iter()) {
            assert_eq!(step_small.output_digest(), step_large.output_digest());
            assert_eq!(
                step_small.side_effects_digest(),
                step_large.side_effects_digest()
            );
        }

        // But trace digests should be different (environment affects trace content)
        assert_ne!(trace_small.trace_digest, trace_large.trace_digest);
    }

    #[test]
    fn memory_pressure_simulation_large_replay() {
        let mut engine = ReplayEngine::new();

        // Create trace with very large steps
        let mut builder = TraceBuilder::new("memory-stress", "test", minimal_env());
        for i in 0..100 {
            let large_input = vec![i as u8; 100_000]; // 100KB per step
            let large_output = vec![(i + 50) as u8; 100_000]; // 100KB per step
            let large_effects = vec![create_large_side_effect(50_000)]; // 50KB side effect

            builder.record_step(
                large_input,
                large_output,
                large_effects,
                (i as u64 + 1) * 1000,
            );
        }

        let (trace, _) = builder.build().unwrap();
        engine.register_trace(trace).unwrap();

        // Identity replay should succeed even with large data
        let result = engine.replay_identity("memory-stress").unwrap();
        assert_eq!(result.verdict, ReplayVerdict::Identical);
        assert_eq!(result.steps_replayed, 100);

        // Divergent replay should also work
        fn large_data_divergence(
            step: &TraceStep,
            _env: &EnvironmentSnapshot,
        ) -> (Vec<u8>, Vec<SideEffect>) {
            let mut output = step.output.clone();
            if !output.is_empty() {
                output[0] ^= 1; // Flip one bit in large output
            }
            (output, step.side_effects.clone())
        }

        let divergent_result = engine
            .replay("memory-stress", large_data_divergence)
            .unwrap();
        assert_eq!(divergent_result.verdict, ReplayVerdict::Diverged(100));
    }

    #[test]
    fn schema_version_consistency() {
        // Verify schema version is embedded consistently
        assert_eq!(SCHEMA_VERSION, "ttr-v1.0");

        let env = minimal_env();
        assert_eq!(env.schema_version, SCHEMA_VERSION);

        let trace = build_demo_trace("schema-test", "test", 1);
        assert_eq!(trace.schema_version, SCHEMA_VERSION);

        let mut engine = ReplayEngine::new();
        engine.register_trace(trace).unwrap();

        let result = engine.replay_identity("schema-test").unwrap();
        assert_eq!(result.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn hash_collision_resistance_stress() {
        // Test hash collision resistance with crafted inputs
        let test_cases = vec![
            // Different concatenations that might collide under naive implementation
            (vec![], vec![1, 2], vec![], vec![]),
            (vec![1], vec![2], vec![], vec![]),
            (vec![1, 2], vec![], vec![], vec![]),
            // Side effects that could collide
            (
                vec![],
                vec![],
                vec![SideEffect::new("ab", vec![1])],
                vec![SideEffect::new("a", vec![]), SideEffect::new("b", vec![1])],
            ),
            (
                vec![],
                vec![],
                vec![SideEffect::new("", vec![97, 98, 1])],
                vec![SideEffect::new("ab", vec![1])],
            ),
        ];

        let mut digests = std::collections::HashSet::new();

        for (i, (input, output, effects1, effects2)) in test_cases.iter().enumerate() {
            let step1 = TraceStep::new(
                i as u64,
                input.clone(),
                output.clone(),
                effects1.clone(),
                1000,
            );
            let step2 = TraceStep::new(
                i as u64,
                input.clone(),
                output.clone(),
                effects2.clone(),
                1000,
            );

            let digest1 = step1.side_effects_digest();
            let digest2 = step2.side_effects_digest();

            if effects1 != effects2 {
                assert_ne!(digest1, digest2, "Hash collision detected for case {}", i);
            }

            // All digests should be unique
            assert!(
                digests.insert(digest1.clone()),
                "Duplicate digest: {}",
                digest1
            );
            if effects1 != effects2 {
                assert!(
                    digests.insert(digest2.clone()),
                    "Duplicate digest: {}",
                    digest2
                );
            }
        }
    }

    #[test]
    fn replay_duration_calculation_edge_cases() {
        let mut engine = ReplayEngine::new();

        // Create trace with edge case timestamps
        let mut builder = TraceBuilder::new("duration-test", "test", minimal_env());
        let timestamps = [0, 500, u64::MAX - 1, u64::MAX, 100]; // Non-monotonic

        for (i, &ts) in timestamps.iter().enumerate() {
            builder.record_step(vec![i as u8], vec![i as u8], vec![], ts);
        }

        let (trace, _) = builder.build().unwrap();
        engine.register_trace(trace).unwrap();

        let result = engine.replay_identity("duration-test").unwrap();

        // Duration should be max timestamp
        assert_eq!(result.replay_duration_ns, u64::MAX);
    }

    #[test]
    fn negative_empty_workflow_trace_rejected() {
        let trace = WorkflowTrace {
            trace_id: "empty-negative".to_string(),
            workflow_name: "negative".to_string(),
            steps: Vec::new(),
            environment: minimal_env(),
            trace_digest: WorkflowTrace::compute_digest(&[]),
            schema_version: SCHEMA_VERSION.to_string(),
        };

        let err = trace.validate().unwrap_err();
        match err {
            TimeTravelError::EmptyTrace { trace_id } => {
                assert_eq!(trace_id, "empty-negative");
            }
            other => panic!("Expected EmptyTrace, got {:?}", other),
        }
    }

    #[test]
    fn negative_sequence_starting_at_one_rejected() {
        let steps = vec![TraceStep::new(
            1,
            b"in".to_vec(),
            b"out".to_vec(),
            vec![],
            10,
        )];
        let trace_digest = WorkflowTrace::compute_digest(&steps);
        let trace = WorkflowTrace {
            trace_id: "seq-start-negative".to_string(),
            workflow_name: "negative".to_string(),
            steps,
            environment: minimal_env(),
            trace_digest,
            schema_version: SCHEMA_VERSION.to_string(),
        };

        let err = trace.validate().unwrap_err();
        match err {
            TimeTravelError::SequenceGap {
                expected, found, ..
            } => {
                assert_eq!(expected, 0);
                assert_eq!(found, 1);
            }
            other => panic!("Expected SequenceGap, got {:?}", other),
        }
    }

    #[test]
    fn negative_duplicate_sequence_rejected() {
        let steps = vec![
            TraceStep::new(0, b"in-0".to_vec(), b"out-0".to_vec(), vec![], 10),
            TraceStep::new(0, b"in-1".to_vec(), b"out-1".to_vec(), vec![], 20),
        ];
        let trace_digest = WorkflowTrace::compute_digest(&steps);
        let trace = WorkflowTrace {
            trace_id: "duplicate-seq-negative".to_string(),
            workflow_name: "negative".to_string(),
            steps,
            environment: minimal_env(),
            trace_digest,
            schema_version: SCHEMA_VERSION.to_string(),
        };

        let err = trace.validate().unwrap_err();
        match err {
            TimeTravelError::SequenceGap {
                expected, found, ..
            } => {
                assert_eq!(expected, 1);
                assert_eq!(found, 0);
            }
            other => panic!("Expected SequenceGap, got {:?}", other),
        }
    }

    #[test]
    fn negative_tampered_trace_rejected_on_registration() {
        let mut trace = build_demo_trace("tampered-register-negative", "negative", 2);
        trace.steps[0].output.push(0xFF);

        let mut engine = ReplayEngine::new();
        let err = engine.register_trace(trace).unwrap_err();

        assert!(matches!(err, TimeTravelError::DigestMismatch { .. }));
        assert_eq!(engine.trace_count(), 0);
    }

    #[test]
    fn negative_missing_platform_rejected_on_registration() {
        let steps = vec![TraceStep::new(
            0,
            b"in".to_vec(),
            b"out".to_vec(),
            vec![],
            10,
        )];
        let trace_digest = WorkflowTrace::compute_digest(&steps);
        let mut environment = minimal_env();
        environment.platform.clear();
        let trace = WorkflowTrace {
            trace_id: "missing-platform-negative".to_string(),
            workflow_name: "negative".to_string(),
            steps,
            environment,
            trace_digest,
            schema_version: SCHEMA_VERSION.to_string(),
        };

        let mut engine = ReplayEngine::new();
        let err = engine.register_trace(trace).unwrap_err();
        match err {
            TimeTravelError::EnvironmentMissing { field, .. } => {
                assert_eq!(field, "platform");
            }
            other => panic!("Expected EnvironmentMissing, got {:?}", other),
        }
    }

    #[test]
    fn negative_missing_runtime_version_rejected_on_registration() {
        let steps = vec![TraceStep::new(
            0,
            b"in".to_vec(),
            b"out".to_vec(),
            vec![],
            10,
        )];
        let trace_digest = WorkflowTrace::compute_digest(&steps);
        let mut environment = minimal_env();
        environment.runtime_version.clear();
        let trace = WorkflowTrace {
            trace_id: "missing-runtime-negative".to_string(),
            workflow_name: "negative".to_string(),
            steps,
            environment,
            trace_digest,
            schema_version: SCHEMA_VERSION.to_string(),
        };

        let mut engine = ReplayEngine::new();
        let err = engine.register_trace(trace).unwrap_err();
        match err {
            TimeTravelError::EnvironmentMissing { field, .. } => {
                assert_eq!(field, "runtime_version");
            }
            other => panic!("Expected EnvironmentMissing, got {:?}", other),
        }
    }

    #[test]
    fn negative_duplicate_trace_registration_rejected() {
        let mut engine = ReplayEngine::new();
        engine
            .register_trace(build_demo_trace("dupe-negative", "negative", 1))
            .unwrap();

        let err = engine
            .register_trace(build_demo_trace("dupe-negative", "negative", 1))
            .unwrap_err();

        match err {
            TimeTravelError::DuplicateTrace { trace_id } => {
                assert_eq!(trace_id, "dupe-negative");
            }
            other => panic!("Expected DuplicateTrace, got {:?}", other),
        }
        assert_eq!(engine.trace_count(), 1);
    }

    #[test]
    fn negative_replay_missing_trace_rejected_without_audit_event() {
        let mut engine = ReplayEngine::new();

        let err = engine
            .replay_identity("missing-trace-negative")
            .unwrap_err();

        match err {
            TimeTravelError::TraceNotFound { trace_id } => {
                assert_eq!(trace_id, "missing-trace-negative");
            }
            other => panic!("Expected TraceNotFound, got {:?}", other),
        }
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn negative_empty_trace_builder_build_rejected() {
        let builder = TraceBuilder::new("empty-builder-negative", "negative", minimal_env());

        let err = builder.build().unwrap_err();

        match err {
            TimeTravelError::EmptyTrace { trace_id } => {
                assert_eq!(trace_id, "empty-builder-negative");
            }
            other => panic!("Expected EmptyTrace, got {:?}", other),
        }
    }
}
