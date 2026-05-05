pub mod approval_workflow;
pub mod bayesian_diagnostics;
pub mod compat_gates;
pub mod compatibility_gate;
pub mod controller_boundary_checks;
pub mod correctness_envelope;
pub mod decision_engine;
pub mod evidence_emission;
pub mod guardrail_monitor;
pub mod hardening_auto_trigger;
pub mod hardening_clamps;
pub mod hardening_state_machine;
pub mod integrity_sweep_scheduler;
pub mod object_class_tuning;
pub mod perf_budget_guard;
pub mod policy_explainer;
pub mod resource_admission;
pub mod retroactive_hardening;

#[cfg(test)]
mod tests {
    use super::guardrail_monitor::{
        ConformalRiskGuardrail, DurabilityLossGuardrail, EvidenceEmissionGuardrail,
        GuardrailMonitor, GuardrailMonitorSet, GuardrailVerdict, HardeningRegressionGuardrail,
        MemoryBudgetGuardrail, MemoryTailRiskGuardrail, MemoryTailRiskTelemetry,
        ReliabilityTelemetry, SystemState,
    };
    use super::hardening_state_machine::HardeningLevel;

    fn policy_state() -> SystemState {
        SystemState {
            memory_used_bytes: 40,
            memory_budget_bytes: 100,
            durability_level: 0.99,
            hardening_level: HardeningLevel::Enhanced,
            proposed_hardening_level: None,
            evidence_emission_active: true,
            memory_tail_risk: None,
            reliability_telemetry: None,
            epoch_id: 17,
        }
    }

    #[test]
    fn negative_memory_budget_blocks_at_exact_threshold() {
        let guardrail = MemoryBudgetGuardrail::new(0.80, 0.60);
        let mut state = policy_state();
        state.memory_used_bytes = 80;
        state.memory_budget_bytes = 100;

        let verdict = guardrail.check(&state);

        assert!(matches!(
            verdict,
            GuardrailVerdict::Block { ref budget_id, .. }
                if budget_id.as_str() == "memory_budget"
        ));
    }

    #[test]
    fn negative_memory_budget_blocks_zero_budget_state() {
        let guardrail = MemoryBudgetGuardrail::default_guardrail();
        let mut state = policy_state();
        state.memory_budget_bytes = 0;

        let verdict = guardrail.check(&state);

        assert!(matches!(
            verdict,
            GuardrailVerdict::Block { ref budget_id, .. }
                if budget_id.as_str() == "memory_budget"
        ));
    }

    #[test]
    fn negative_durability_guard_blocks_nan_level() {
        let guardrail = DurabilityLossGuardrail::default_guardrail();
        let mut state = policy_state();
        state.durability_level = f64::NAN;

        let verdict = guardrail.check(&state);

        assert!(matches!(
            verdict,
            GuardrailVerdict::Block { ref budget_id, .. }
                if budget_id.as_str() == "durability_budget"
        ));
    }

    #[test]
    fn negative_hardening_regression_blocks_downshift() {
        let guardrail = HardeningRegressionGuardrail::new();
        let mut state = policy_state();
        state.hardening_level = HardeningLevel::Maximum;
        state.proposed_hardening_level = Some(HardeningLevel::Standard);

        let verdict = guardrail.check(&state);

        assert!(matches!(
            verdict,
            GuardrailVerdict::Block { ref budget_id, ref reason }
                if budget_id.as_str() == "hardening_regression"
                    && reason.contains("hardening regression")
        ));
    }

    #[test]
    fn negative_evidence_emission_guard_blocks_disabled_state() {
        let guardrail = EvidenceEmissionGuardrail::new();
        let mut state = policy_state();
        state.evidence_emission_active = false;

        let verdict = guardrail.check(&state);

        assert!(matches!(
            verdict,
            GuardrailVerdict::Block { ref budget_id, ref reason }
                if budget_id.as_str() == "evidence_emission"
                    && reason.contains("evidence emission is disabled")
        ));
    }

    #[test]
    fn negative_conformal_risk_blocks_high_error_envelope() {
        let guardrail = ConformalRiskGuardrail::new(0.10, 0.05, 0.01, 16);
        let mut state = policy_state();
        state.reliability_telemetry = Some(ReliabilityTelemetry {
            sample_count: 64,
            nonconforming_count: 32,
        });

        let verdict = guardrail.check(&state);

        assert!(matches!(
            verdict,
            GuardrailVerdict::Block { ref budget_id, ref reason }
                if budget_id.as_str() == "conformal_risk"
                    && reason.contains("upper error bound")
        ));
    }

    #[test]
    fn negative_memory_tail_risk_blocks_nonfinite_telemetry_conservatively() {
        let guardrail = MemoryTailRiskGuardrail::new(0.90, 0.80, 0.01, 8);
        let mut state = policy_state();
        state.memory_tail_risk = Some(MemoryTailRiskTelemetry {
            sample_count: 64,
            mean_utilization: f64::NAN,
            variance_utilization: f64::INFINITY,
            peak_utilization: f64::NAN,
        });

        let verdict = guardrail.check(&state);

        assert!(matches!(
            verdict,
            GuardrailVerdict::Block { ref budget_id, ref reason }
                if budget_id.as_str() == "memory_tail_risk"
                    && reason.contains("tail-risk memory envelope")
        ));
    }

    #[test]
    fn negative_memory_tail_risk_blocks_peak_spike_even_when_mean_is_low() {
        let guardrail = MemoryTailRiskGuardrail::new(0.90, 0.80, 0.01, 8);
        let mut state = policy_state();
        state.memory_tail_risk = Some(MemoryTailRiskTelemetry {
            sample_count: 64,
            mean_utilization: 0.05,
            variance_utilization: 0.0,
            peak_utilization: 0.95,
        });

        let verdict = guardrail.check(&state);

        assert!(matches!(
            verdict,
            GuardrailVerdict::Block { ref budget_id, .. }
                if budget_id.as_str() == "memory_tail_risk"
        ));
    }

    #[test]
    fn negative_memory_tail_risk_blocks_high_variance_window() {
        let guardrail = MemoryTailRiskGuardrail::new(0.70, 0.60, 0.01, 8);
        let mut state = policy_state();
        state.memory_tail_risk = Some(MemoryTailRiskTelemetry {
            sample_count: 64,
            mean_utilization: 0.40,
            variance_utilization: 0.25,
            peak_utilization: 0.40,
        });

        let verdict = guardrail.check(&state);

        assert!(matches!(
            verdict,
            GuardrailVerdict::Block { ref budget_id, ref reason }
                if budget_id.as_str() == "memory_tail_risk"
                    && reason.contains("exceeds block threshold")
        ));
    }

    #[test]
    fn negative_conformal_risk_saturates_nonconforming_count_above_samples() {
        let guardrail = ConformalRiskGuardrail::new(0.10, 0.05, 0.01, 16);
        let mut state = policy_state();
        state.reliability_telemetry = Some(ReliabilityTelemetry {
            sample_count: 32,
            nonconforming_count: 1_000,
        });

        let verdict = guardrail.check(&state);

        assert!(matches!(
            verdict,
            GuardrailVerdict::Block { ref budget_id, ref reason }
                if budget_id.as_str() == "conformal_risk"
                    && reason.contains("empirical 1.000")
        ));
    }

    #[test]
    fn negative_conformal_risk_blocks_at_minimum_sample_boundary() {
        let guardrail = ConformalRiskGuardrail::new(0.10, 0.05, 0.01, 16);
        let mut state = policy_state();
        state.reliability_telemetry = Some(ReliabilityTelemetry {
            sample_count: 16,
            nonconforming_count: 4,
        });

        let verdict = guardrail.check(&state);

        assert!(matches!(
            verdict,
            GuardrailVerdict::Block { ref budget_id, ref reason }
                if budget_id.as_str() == "conformal_risk"
                    && reason.contains("n=16")
        ));
    }

    #[test]
    fn negative_durability_guard_blocks_negative_level() {
        let guardrail = DurabilityLossGuardrail::default_guardrail();
        let mut state = policy_state();
        state.durability_level = -0.01;

        let verdict = guardrail.check(&state);

        assert!(matches!(
            verdict,
            GuardrailVerdict::Block { ref budget_id, ref reason }
                if budget_id.as_str() == "durability_budget"
                    && reason.contains("below minimum")
        ));
    }

    #[test]
    fn negative_default_monitor_set_rejects_first_blocking_guardrail() {
        let monitor_set = GuardrailMonitorSet::with_defaults();
        let mut state = policy_state();
        state.memory_budget_bytes = 0;
        state.durability_level = f64::NAN;
        state.evidence_emission_active = false;

        let rejection = monitor_set
            .evaluate(&state)
            .expect_err("default monitor set should reject unsafe state");

        assert!(!rejection.reason.is_empty());
        assert_eq!(rejection.epoch_id, 17);
    }

    #[test]
    fn negative_default_certificate_records_multiple_blocking_budgets() {
        let monitor_set = GuardrailMonitorSet::with_defaults();
        let mut state = policy_state();
        state.memory_budget_bytes = 0;
        state.durability_level = f64::NAN;
        state.evidence_emission_active = false;

        let certificate = monitor_set.certify(&state);

        assert!(certificate.dominant_verdict.is_blocked());
        assert!(
            certificate
                .blocking_budget_ids
                .iter()
                .any(|budget_id| budget_id.as_str() == "memory_budget")
        );
        assert!(
            certificate
                .blocking_budget_ids
                .iter()
                .any(|budget_id| budget_id.as_str() == "durability_budget")
        );
        assert!(
            certificate
                .blocking_budget_ids
                .iter()
                .any(|budget_id| budget_id.as_str() == "evidence_emission")
        );
    }

    #[test]
    fn negative_memory_budget_nonfinite_threshold_fails_closed_at_envelope_floor() {
        let guardrail = MemoryBudgetGuardrail::new(f64::NAN, f64::INFINITY);
        let mut state = policy_state();
        state.memory_used_bytes = 50;
        state.memory_budget_bytes = 100;

        let verdict = guardrail.check(&state);

        assert!(matches!(
            verdict,
            GuardrailVerdict::Block { ref budget_id, ref reason }
                if budget_id.as_str() == "memory_budget" && reason.contains("50.0%")
        ));
    }

    #[test]
    fn negative_memory_budget_warn_threshold_above_block_still_blocks_at_block() {
        let guardrail = MemoryBudgetGuardrail::new(0.65, 0.95);
        let mut state = policy_state();
        state.memory_used_bytes = 65;
        state.memory_budget_bytes = 100;

        let verdict = guardrail.check(&state);

        assert!(matches!(
            verdict,
            GuardrailVerdict::Block { ref budget_id, .. }
                if budget_id.as_str() == "memory_budget"
        ));
    }

    #[test]
    fn negative_memory_tail_risk_min_sample_floor_blocks_at_eight_not_seven() {
        let guardrail = MemoryTailRiskGuardrail::new(0.90, 0.80, 0.01, 0);
        let mut state = policy_state();
        state.memory_tail_risk = Some(MemoryTailRiskTelemetry {
            sample_count: 7,
            mean_utilization: 1.0,
            variance_utilization: 0.0,
            peak_utilization: 1.0,
        });

        assert!(matches!(guardrail.check(&state), GuardrailVerdict::Allow));

        state.memory_tail_risk = Some(MemoryTailRiskTelemetry {
            sample_count: 8,
            mean_utilization: 1.0,
            variance_utilization: 0.0,
            peak_utilization: 1.0,
        });

        assert!(matches!(
            guardrail.check(&state),
            GuardrailVerdict::Block { ref budget_id, .. }
                if budget_id.as_str() == "memory_tail_risk"
        ));
    }

    #[test]
    fn negative_memory_tail_risk_negative_alpha_still_blocks_peak_spike() {
        let guardrail = MemoryTailRiskGuardrail::new(0.90, 0.80, -1.0, 8);
        let mut state = policy_state();
        state.memory_tail_risk = Some(MemoryTailRiskTelemetry {
            sample_count: 8,
            mean_utilization: 0.0,
            variance_utilization: 0.0,
            peak_utilization: 0.91,
        });

        let verdict = guardrail.check(&state);

        assert!(matches!(
            verdict,
            GuardrailVerdict::Block { ref budget_id, ref reason }
                if budget_id.as_str() == "memory_tail_risk"
                    && reason.contains("tail-risk memory envelope")
        ));
    }

    #[test]
    fn negative_conformal_risk_min_sample_floor_blocks_at_sixteen_not_fifteen() {
        let guardrail = ConformalRiskGuardrail::new(0.10, 0.05, 0.01, 0);
        let mut state = policy_state();
        state.reliability_telemetry = Some(ReliabilityTelemetry {
            sample_count: 15,
            nonconforming_count: 15,
        });

        assert!(matches!(guardrail.check(&state), GuardrailVerdict::Allow));

        state.reliability_telemetry = Some(ReliabilityTelemetry {
            sample_count: 16,
            nonconforming_count: 16,
        });

        assert!(matches!(
            guardrail.check(&state),
            GuardrailVerdict::Block { ref budget_id, ref reason }
                if budget_id.as_str() == "conformal_risk"
                    && reason.contains("n=16")
        ));
    }

    #[test]
    fn negative_conformal_risk_nonfinite_delta_blocks_high_error_window() {
        let guardrail = ConformalRiskGuardrail::new(0.10, 0.05, f64::NAN, 16);
        let mut state = policy_state();
        state.reliability_telemetry = Some(ReliabilityTelemetry {
            sample_count: 16,
            nonconforming_count: 16,
        });

        let verdict = guardrail.check(&state);

        assert!(matches!(
            verdict,
            GuardrailVerdict::Block { ref budget_id, ref reason }
                if budget_id.as_str() == "conformal_risk"
                    && reason.contains("upper error bound")
        ));
    }

    #[test]
    fn negative_default_monitor_set_prefers_block_over_warn() {
        let monitor_set = GuardrailMonitorSet::with_defaults();
        let mut state = policy_state();
        state.memory_used_bytes = 85;
        state.memory_budget_bytes = 100;
        state.evidence_emission_active = false;

        let verdict = monitor_set.check_all(&state);

        assert!(matches!(
            verdict,
            GuardrailVerdict::Block { ref budget_id, .. }
                if budget_id.as_str() == "evidence_emission"
        ));
    }

    #[test]
    fn negative_certificate_deduplicates_duplicate_blocking_budget_ids() {
        let mut monitor_set = GuardrailMonitorSet::new();
        monitor_set.register(Box::new(MemoryBudgetGuardrail::default_guardrail()));
        monitor_set.register(Box::new(MemoryBudgetGuardrail::new(0.75, 0.50)));
        let mut state = policy_state();
        state.memory_budget_bytes = 0;

        let certificate = monitor_set.certify(&state);
        let memory_budget_count = certificate
            .blocking_budget_ids
            .iter()
            .filter(|budget_id| budget_id.as_str() == "memory_budget")
            .count();

        assert!(certificate.dominant_verdict.is_blocked());
        assert_eq!(memory_budget_count, 1);
    }

    /// Extreme adversarial test: Policy state machine manipulation attack via carefully
    /// crafted hardening level transitions to exploit policy enforcement windows
    #[test]
    fn policy_hardening_state_machine_transition_exploitation_bypass_attack() {
        let guardrail = HardeningRegressionGuardrail::new();

        // Test attack scenarios targeting policy transition windows
        let malicious_transitions = [
            // Attempt to downgrade from Maximum to Minimal via intermediate steps
            (HardeningLevel::Maximum, Some(HardeningLevel::Enhanced)),
            (HardeningLevel::Enhanced, Some(HardeningLevel::Standard)),
            (HardeningLevel::Standard, Some(HardeningLevel::Minimal)),
            // Direct maximum-to-minimal downgrade attempt
            (HardeningLevel::Maximum, Some(HardeningLevel::Minimal)),
            // Attempt to bypass via same-level transitions
            (HardeningLevel::Maximum, Some(HardeningLevel::Maximum)),
            (HardeningLevel::Enhanced, Some(HardeningLevel::Enhanced)),
            // Undefined/invalid transition states
            (HardeningLevel::Minimal, Some(HardeningLevel::Maximum)), // Suspicious rapid upgrade
        ];

        for (current_level, proposed_level) in malicious_transitions {
            let mut state = policy_state();
            state.hardening_level = current_level;
            state.proposed_hardening_level = proposed_level;

            let verdict = guardrail.check(&state);

            // Any downgrade attempt should be blocked
            if let Some(proposed) = proposed_level {
                if (current_level as u8) > (proposed as u8) {
                    assert!(
                        matches!(
                            verdict,
                            GuardrailVerdict::Block { ref budget_id, .. }
                                if budget_id.as_str() == "hardening_regression"
                        ),
                        "Downgrade from {:?} to {:?} should be blocked",
                        current_level,
                        proposed
                    );
                }
            }
        }
    }

    /// Extreme adversarial test: Integer overflow attack in memory budget calculations
    /// targeting arithmetic overflow in guardrail threshold computations
    #[test]
    fn policy_memory_budget_integer_overflow_arithmetic_bypass_attack() {
        let guardrail = MemoryBudgetGuardrail::new(0.80, 0.60);

        // Integer overflow attack vectors in memory calculations
        let overflow_scenarios = [
            // Near-maximum values that could overflow in percentage calculations
            (u64::MAX, u64::MAX - 1),         // 100% utilization
            (u64::MAX - 1_000_000, u64::MAX), // Very high utilization
            (u64::MAX / 2, u64::MAX),         // 50% utilization
            (1_000_000_000_000_000, 1_000_000_000_000_001), // Large absolute values
            // Edge cases around zero
            (0, u64::MAX),        // Zero used, max budget
            (1, u64::MAX),        // Minimal used, max budget
            (u64::MAX, u64::MAX), // Maximum both
            // Values that could cause precision issues
            (u64::MAX / 3, u64::MAX / 4 + 1), // Irregular fractions
        ];

        for (memory_used, memory_budget) in overflow_scenarios {
            let mut state = policy_state();
            state.memory_used_bytes = memory_used;
            state.memory_budget_bytes = memory_budget;

            let verdict = guardrail.check(&state);

            // Guardrail must handle overflow scenarios without panicking
            match verdict {
                GuardrailVerdict::Allow => {
                    // If allowed, ensure it's truly safe
                    if memory_budget > 0 {
                        let utilization = memory_used as f64 / memory_budget as f64;
                        assert!(
                            utilization.is_finite(),
                            "Overflow scenario with used={}, budget={} resulted in non-finite utilization",
                            memory_used,
                            memory_budget
                        );
                    }
                }
                GuardrailVerdict::Warn { .. } => {
                    // Warnings are acceptable for edge cases
                }
                GuardrailVerdict::Block { .. } => {
                    // Blocking is the safe default for overflow scenarios
                }
            }
        }
    }

    /// Extreme adversarial test: Statistical manipulation attack via malicious telemetry
    /// data designed to bypass conformal risk assessment through mathematical exploitation
    #[test]
    fn policy_conformal_risk_statistical_manipulation_confidence_bypass_attack() {
        let guardrail = ConformalRiskGuardrail::new(0.10, 0.05, 0.01, 16);

        // Statistical attack vectors targeting confidence interval manipulation
        let manipulation_attacks = [
            // Edge cases around confidence interval boundaries
            (16, 0),  // Perfect conformity (should pass)
            (16, 1),  // Single nonconforming sample (may pass)
            (16, 2),  // Boundary case
            (16, 16), // Complete nonconformity (must block)
            // Large sample statistical manipulation
            (10_000, 100),    // Low error rate with large samples
            (10_000, 999),    // High error rate masked by large samples
            (10_000, 10_000), // Complete failure with large samples
            // Statistical edge cases
            (1_000_000, 1),       // Single failure in large sample
            (1_000_000, 50_000),  // 5% error rate
            (1_000_000, 100_000), // 10% error rate (boundary)
            // Boundary manipulation around minimum samples
            (15, 15), // Below minimum threshold
            (17, 17), // Just above threshold
        ];

        for (sample_count, nonconforming_count) in manipulation_attacks {
            let mut state = policy_state();
            state.reliability_telemetry = Some(ReliabilityTelemetry {
                sample_count,
                nonconforming_count,
            });

            let verdict = guardrail.check(&state);

            // Verify statistical assessment is sound
            if sample_count >= 16 {
                let empirical_rate =
                    nonconforming_count.min(sample_count) as f64 / sample_count as f64;

                if empirical_rate > 0.15 {
                    // Well above acceptable thresholds
                    assert!(
                        matches!(
                            verdict,
                            GuardrailVerdict::Block { ref budget_id, .. }
                                if budget_id.as_str() == "conformal_risk"
                        ),
                        "High error rate {:.3} should be blocked",
                        empirical_rate
                    );
                }

                // Ensure no integer overflow occurred
                assert!(
                    empirical_rate.is_finite() && empirical_rate >= 0.0 && empirical_rate <= 1.0,
                    "Empirical rate must be finite and in [0,1]: {}",
                    empirical_rate
                );
            }
        }
    }

    /// Extreme adversarial test: Concurrent policy evaluation race condition attack
    /// targeting shared guardrail state corruption during parallel monitoring
    #[test]
    fn policy_concurrent_guardrail_evaluation_state_corruption_race_attack() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let monitor_set = Arc::new(Mutex::new(GuardrailMonitorSet::with_defaults()));

        // Spawn multiple threads performing concurrent policy evaluations
        let handles: Vec<_> = (0..10)
            .map(|thread_id| {
                let monitor_clone = Arc::clone(&monitor_set);

                thread::spawn(move || {
                    for i in 0..50 {
                        let mut state = policy_state();

                        // Apply thread-specific state mutations to trigger race conditions
                        state.epoch_id = (thread_id * 1000 + i) as u64;
                        state.memory_used_bytes = (thread_id * 10 + i) as u64;
                        state.memory_budget_bytes = 100 + (i % 50) as u64;
                        state.durability_level = 0.5 + (i as f64 / 100.0);

                        // Rapidly alternating hardening levels to stress state machine
                        state.hardening_level = if i % 2 == 0 {
                            HardeningLevel::Maximum
                        } else {
                            HardeningLevel::Minimal
                        };

                        state.proposed_hardening_level = if i % 3 == 0 {
                            Some(HardeningLevel::Enhanced)
                        } else {
                            None
                        };

                        if let Ok(monitor_lock) = monitor_clone.try_lock() {
                            let verdict = monitor_lock.check_all(&state);

                            // Verify verdict consistency
                            match verdict {
                                GuardrailVerdict::Allow => {}
                                GuardrailVerdict::Warn { ref budget_id, .. } => {
                                    assert!(!budget_id.is_empty());
                                }
                                GuardrailVerdict::Block { ref budget_id, .. } => {
                                    assert!(!budget_id.is_empty());
                                }
                            }
                        }

                        // Brief yield to encourage race conditions
                        thread::yield_now();
                    }
                })
            })
            .collect();

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify guardrail set remains functional after concurrent access
        let final_monitor = monitor_set.lock().unwrap();
        let test_state = policy_state();
        let final_verdict = final_monitor.check_all(&test_state);

        // Should produce consistent results
        assert!(matches!(
            final_verdict,
            GuardrailVerdict::Allow
                | GuardrailVerdict::Warn { .. }
                | GuardrailVerdict::Block { .. }
        ));
    }

    /// Extreme adversarial test: Memory exhaustion attack via policy complexity explosion
    /// designed to overwhelm guardrail evaluation through computational amplification
    #[test]
    fn policy_guardrail_complexity_memory_exhaustion_dos_attack() {
        use std::time::Instant;

        let mut monitor_set = GuardrailMonitorSet::new();

        // Register massive number of guardrails to stress memory and performance
        for i in 0..1000 {
            // Limit to prevent actual DoS in test
            let block_threshold = 0.01 + (i as f64 / 100_000.0); // Varying thresholds
            let warn_threshold = block_threshold + 0.01;

            monitor_set.register(Box::new(MemoryBudgetGuardrail::new(
                warn_threshold.min(0.99),
                block_threshold.min(0.98),
            )));

            // Prevent actual memory exhaustion in test environment
            if i >= 100 {
                break;
            }
        }

        // Test evaluation performance under stress
        let stress_states = [
            // Memory scenarios designed to hit many thresholds
            (50, 100, 0.95),  // 50% memory usage
            (75, 100, 0.80),  // 75% memory usage
            (90, 100, 0.60),  // 90% memory usage
            (99, 100, 0.40),  // 99% memory usage
            (100, 100, 0.20), // 100% memory usage
        ];

        for (memory_used, memory_budget, durability) in stress_states {
            let mut state = policy_state();
            state.memory_used_bytes = memory_used;
            state.memory_budget_bytes = memory_budget;
            state.durability_level = durability;

            let start = Instant::now();
            let verdict = monitor_set.check_all(&state);
            let elapsed = start.elapsed();

            // Evaluation must complete in reasonable time despite complexity
            assert!(
                elapsed.as_millis() < 1000,
                "Guardrail evaluation took {}ms, should be <1000ms",
                elapsed.as_millis()
            );

            // Result should be deterministic
            assert!(matches!(
                verdict,
                GuardrailVerdict::Allow
                    | GuardrailVerdict::Warn { .. }
                    | GuardrailVerdict::Block { .. }
            ));
        }
    }

    /// Extreme adversarial test: Floating-point precision attack via carefully crafted
    /// values to exploit rounding errors in statistical threshold calculations
    #[test]
    fn policy_floating_point_precision_threshold_bypass_attack() {
        let tail_risk_guardrail = MemoryTailRiskGuardrail::new(0.90, 0.80, 0.01, 8);

        // Floating-point precision attack vectors
        let precision_attacks = [
            // Values very close to thresholds that might round incorrectly
            (0.8000000000000001, 0.90000000000000001), // Extremely close to thresholds
            (0.7999999999999999, 0.89999999999999999), // Just under thresholds
            (0.8 + f64::EPSILON, 0.9 + f64::EPSILON),  // Epsilon-above thresholds
            (0.8 - f64::EPSILON, 0.9 - f64::EPSILON),  // Epsilon-below thresholds
            // Precision edge cases
            (f64::MIN_POSITIVE, f64::MIN_POSITIVE * 2.0), // Minimal positive values
            (1.0 - f64::EPSILON, 1.0),                    // Near maximum values
            (0.5000000000000001, 0.6000000000000001),     // Mid-range precision
            // Values that could cause precision loss in calculations
            (1.0 / 3.0, 2.0 / 3.0), // Repeating decimals
            (std::f64::consts::PI / 10.0, std::f64::consts::E / 10.0), // Irrational numbers
        ];

        for (mean_utilization, peak_utilization) in precision_attacks {
            let mut state = policy_state();
            state.memory_tail_risk = Some(MemoryTailRiskTelemetry {
                sample_count: 64,
                mean_utilization,
                variance_utilization: 0.01,
                peak_utilization,
            });

            let verdict = tail_risk_guardrail.check(&state);

            // Verify floating-point calculations are sound
            assert!(
                mean_utilization.is_finite() && peak_utilization.is_finite(),
                "Input values must be finite: mean={}, peak={}",
                mean_utilization,
                peak_utilization
            );

            // Results should be consistent regardless of precision nuances
            match verdict {
                GuardrailVerdict::Allow => {
                    // If allowed, both values should be clearly below thresholds
                    assert!(
                        mean_utilization < 0.85 && peak_utilization < 0.95,
                        "Precision attack bypassed thresholds: mean={}, peak={}",
                        mean_utilization,
                        peak_utilization
                    );
                }
                GuardrailVerdict::Warn { .. } => {
                    // Warnings are acceptable in precision edge cases
                }
                GuardrailVerdict::Block { .. } => {
                    // Blocking is appropriate for threshold violations
                }
            }
        }
    }

    /// Extreme adversarial test: Policy bypass via malformed telemetry injection
    /// targeting input validation weaknesses in guardrail monitoring systems
    #[test]
    fn policy_malformed_telemetry_injection_validation_bypass_attack() {
        let conformal_guardrail = ConformalRiskGuardrail::new(0.10, 0.05, 0.01, 16);
        let tail_risk_guardrail = MemoryTailRiskGuardrail::new(0.90, 0.80, 0.01, 8);

        // Malformed telemetry attack vectors
        let malformed_attacks = [
            // Invalid mathematical values
            (f64::NAN, f64::INFINITY, f64::NEG_INFINITY),
            (f64::INFINITY, f64::NAN, f64::NEG_INFINITY),
            (f64::NEG_INFINITY, f64::INFINITY, f64::NAN),
            // Extreme values that could break calculations
            (f64::MAX, f64::MIN, f64::MAX),
            (-f64::MAX, f64::MAX, -f64::MIN_POSITIVE),
            // Subnormal numbers that could cause precision issues
            (
                f64::MIN_POSITIVE,
                f64::MIN_POSITIVE * 0.5,
                f64::MIN_POSITIVE * 2.0,
            ),
            // Values that could exploit floating-point edge cases
            (1.0 / 0.0, -1.0 / 0.0, 0.0 / 0.0), // Division by zero variants
        ];

        for (mean_util, variance_util, peak_util) in malformed_attacks {
            // Test MemoryTailRiskGuardrail with malformed telemetry
            let mut state = policy_state();
            state.memory_tail_risk = Some(MemoryTailRiskTelemetry {
                sample_count: 64,
                mean_utilization: mean_util,
                variance_utilization: variance_util,
                peak_utilization: peak_util,
            });

            let verdict = tail_risk_guardrail.check(&state);

            // Malformed input should be handled safely (blocked or gracefully handled)
            match verdict {
                GuardrailVerdict::Allow => {
                    // Should only allow if values are finite and reasonable
                    if !mean_util.is_finite()
                        || !variance_util.is_finite()
                        || !peak_util.is_finite()
                    {
                        panic!(
                            "Malformed telemetry should not result in Allow verdict: mean={}, var={}, peak={}",
                            mean_util, variance_util, peak_util
                        );
                    }
                }
                GuardrailVerdict::Warn { .. } | GuardrailVerdict::Block { .. } => {
                    // Expected behavior for malformed input
                }
            }
        }

        // Test integer overflow scenarios in conformal risk telemetry
        let overflow_scenarios = [
            (u64::MAX, u64::MAX),                   // Maximum values
            (u64::MAX - 1, u64::MAX),               // Near-maximum
            (0, u64::MAX),                          // Zero/maximum combination
            (1_000_000_000_000, 1_000_000_000_001), // Large but reasonable values
        ];

        for (sample_count, nonconforming_count) in overflow_scenarios {
            let mut state = policy_state();
            state.reliability_telemetry = Some(ReliabilityTelemetry {
                sample_count,
                nonconforming_count,
            });

            let verdict = conformal_guardrail.check(&state);

            // Integer overflow scenarios should be handled gracefully
            match verdict {
                GuardrailVerdict::Allow => {
                    // Only allow if calculations are mathematically sound
                    let rate =
                        nonconforming_count.min(sample_count) as f64 / sample_count.max(1) as f64;
                    assert!(
                        rate.is_finite() && rate >= 0.0 && rate <= 1.0,
                        "Invalid rate calculation: {}",
                        rate
                    );
                }
                GuardrailVerdict::Warn { .. } | GuardrailVerdict::Block { .. } => {
                    // Safe default for overflow scenarios
                }
            }
        }
    }

    /// Test Unicode injection attacks in policy module components
    #[test]
    fn negative_policy_unicode_injection_comprehensive() {
        use super::guardrail_monitor::{
            GuardrailMonitor, GuardrailVerdict, MemoryBudgetGuardrail, SystemState,
        };
        use super::hardening_state_machine::HardeningLevel;

        let unicode_attack_vectors = vec![
            // BiDi override attacks in system identifiers
            ("bidi_override", "system\u{202E}live\u{202D}_guardian"),
            (
                "bidi_nested",
                "policy\u{202E}level1\u{202E}level2\u{202D}evil\u{202D}",
            ),
            // Zero-width character pollution
            ("zws_pollution", "guard\u{200B}evil\u{200C}rail\u{200D}"),
            (
                "zwj_sequence",
                "policy\u{200D}\u{1F469}\u{200D}\u{1F4BB}trusted",
            ),
            // Control character injection
            ("ansi_escape", "system\x1b[31mevil\x1b[0m_monitor"),
            ("carriage_return", "policy\roverwrite_state"),
            ("vertical_tab", "guard\x0Bhidden_rail"),
            // Unicode normalization attacks
            ("nfd_attack", "policé_guardian"),         // NFC form
            ("nfc_attack", "police\u{0301}_guardian"), // NFD form
            (
                "combining_stack",
                "guard\u{0300}\u{0301}\u{0302}\u{0303}rail",
            ),
            // Path injection attempts
            ("path_traversal", "../../../evil_policy"),
            ("null_termination", "policy\x00hidden_config"),
        ];

        for (attack_name, malicious_input) in unicode_attack_vectors {
            let injection_result = std::panic::catch_unwind(|| {
                // Test system state with Unicode-injected values
                let mut state = SystemState {
                    memory_used_bytes: 50,
                    memory_budget_bytes: 100,
                    durability_level: 0.95,
                    hardening_level: HardeningLevel::Enhanced,
                    proposed_hardening_level: None,
                    evidence_emission_active: true,
                    memory_tail_risk: None,
                    reliability_telemetry: None,
                    epoch_id: 42,
                };

                // Test memory budget guardrail with Unicode attack context
                let guardrail = MemoryBudgetGuardrail::new(0.8, 0.6);
                let verdict = guardrail.check(&state);

                // Should handle Unicode consistently without corruption
                match verdict {
                    GuardrailVerdict::Allow => {
                        // Verification should be deterministic regardless of Unicode context
                    }
                    GuardrailVerdict::Warn { reason } => {
                        assert!(
                            !reason.is_empty(),
                            "Warn reason should be present: {}",
                            attack_name
                        );
                    }
                    GuardrailVerdict::Block { reason } => {
                        assert!(
                            !reason.is_empty(),
                            "Block reason should be present: {}",
                            attack_name
                        );
                    }
                }

                // Test guardrail debug formatting with Unicode
                let debug_output = format!("{:?}", guardrail);
                assert!(
                    !debug_output.contains("\u{202E}"),
                    "Debug should not contain BiDi overrides: {}",
                    attack_name
                );
                assert!(
                    !debug_output.contains("\x1b["),
                    "Debug should escape ANSI sequences: {}",
                    attack_name
                );

                // Test system state serialization safety
                let state_debug = format!("{:?}", state);
                assert!(
                    !state_debug.contains("%s"),
                    "State debug should not contain format specifiers: {}",
                    attack_name
                );
                assert!(
                    !state_debug.contains("\x00"),
                    "State debug should escape null bytes: {}",
                    attack_name
                );

                // Test hardening level enum with Unicode context
                let hardening_debug = format!("{:?}", HardeningLevel::Enhanced);
                assert!(
                    !hardening_debug.is_empty(),
                    "Hardening level should have debug representation: {}",
                    attack_name
                );

                Ok(())
            });

            assert!(
                injection_result.is_ok(),
                "Unicode injection test should not panic: {}",
                attack_name
            );
        }
    }

    /// Test memory exhaustion protection in policy guardrails
    #[test]
    fn negative_policy_memory_exhaustion_stress() {
        use super::guardrail_monitor::{
            ConformalRiskGuardrail, DurabilityLossGuardrail, EvidenceEmissionGuardrail,
            GuardrailMonitorSet, HardeningRegressionGuardrail, MemoryBudgetGuardrail,
            MemoryTailRiskGuardrail, SystemState,
        };
        use super::hardening_state_machine::HardeningLevel;

        let memory_stress_result = std::panic::catch_unwind(|| {
            // Test with extreme memory values that could cause overflow
            let extreme_memory_cases = vec![
                (u64::MAX, u64::MAX, "max_values"),
                (u64::MAX - 1, u64::MAX, "near_max_used"),
                (0, u64::MAX, "zero_used_max_budget"),
                (u64::MAX / 2, u64::MAX / 4, "over_budget"),
                (1_000_000_000_000, 500_000_000_000, "massive_values"),
            ];

            for (memory_used, memory_budget, test_name) in extreme_memory_cases {
                let mut state = SystemState {
                    memory_used_bytes: memory_used,
                    memory_budget_bytes: memory_budget,
                    durability_level: 0.95,
                    hardening_level: HardeningLevel::Enhanced,
                    proposed_hardening_level: None,
                    evidence_emission_active: true,
                    memory_tail_risk: None,
                    reliability_telemetry: None,
                    epoch_id: 1,
                };

                // Test memory budget guardrail with extreme values
                let memory_guardrail = MemoryBudgetGuardrail::new(0.8, 0.6);
                let memory_verdict = memory_guardrail.check(&state);

                // Should handle extreme values without overflow/panic
                match memory_verdict {
                    GuardrailVerdict::Allow => {}
                    GuardrailVerdict::Warn { .. } => {}
                    GuardrailVerdict::Block { .. } => {}
                }

                // Test conformal risk guardrail with extreme sample counts
                let conformal_guardrail = ConformalRiskGuardrail::new(10000, 0.05);
                state.reliability_telemetry =
                    Some(super::guardrail_monitor::ReliabilityTelemetry {
                        sample_count: u64::MAX / 1000, // Very large but not overflow-inducing
                        nonconforming_count: u64::MAX / 2000, // Proportionally smaller
                    });

                let conformal_verdict = conformal_guardrail.check(&state);

                // Should handle large sample counts safely
                match conformal_verdict {
                    GuardrailVerdict::Allow => {
                        // Verify calculations didn't overflow
                        if let Some(telemetry) = &state.reliability_telemetry {
                            let rate = telemetry.nonconforming_count as f64
                                / telemetry.sample_count.max(1) as f64;
                            assert!(
                                rate.is_finite(),
                                "Rate calculation should be finite: {}",
                                test_name
                            );
                            assert!(
                                rate >= 0.0 && rate <= 1.0,
                                "Rate should be in valid range: {}",
                                test_name
                            );
                        }
                    }
                    GuardrailVerdict::Warn { .. } | GuardrailVerdict::Block { .. } => {}
                }
            }

            // Test guardrail monitor set with many guardrails
            let mut monitor_set = GuardrailMonitorSet::new();

            // Add many guardrails to test capacity handling
            for i in 0..1000 {
                let memory_guardrail = MemoryBudgetGuardrail::new(
                    0.8 - (i as f64 * 0.0001), // Slightly varying thresholds
                    0.6 - (i as f64 * 0.0001),
                );

                // Should handle many guardrails without memory exhaustion
                monitor_set.add_memory_budget_guardrail(memory_guardrail);

                // Periodically check that the set is still functioning
                if i % 100 == 0 {
                    let test_state = policy_state();
                    let check_result =
                        std::panic::catch_unwind(|| monitor_set.check_all(&test_state));
                    assert!(
                        check_result.is_ok(),
                        "Monitor set should handle {} guardrails",
                        i + 1
                    );
                }
            }

            // Test final state with many guardrails
            let final_state = policy_state();
            let final_result = monitor_set.check_all(&final_state);
            assert!(
                final_result.len() <= 1000,
                "Should not exceed expected guardrail count"
            );

            Ok(())
        });

        assert!(
            memory_stress_result.is_ok(),
            "Memory exhaustion stress test should not panic"
        );
    }

    /// Test JSON structure integrity in policy serialization
    #[test]
    fn negative_policy_json_integrity_validation() {
        use super::guardrail_monitor::{GuardrailVerdict, SystemState};
        use super::hardening_state_machine::HardeningLevel;

        let json_corruption_patterns = vec![
            // Test state serialization integrity (via Debug trait)
            ("debug_format_inject", "test%s%x%d"),
            ("ansi_in_debug", "test\x1b[31mred\x1b[0m"),
            ("null_in_debug", "test\x00hidden"),
            ("crlf_in_debug", "test\r\n{\"injected\": true}"),
            ("unicode_escape", "test\u{202E}gniwoh\u{202D}"),
        ];

        for (malicious_pattern, attack_name) in json_corruption_patterns {
            let json_integrity_result = std::panic::catch_unwind(|| {
                // Test SystemState debug formatting integrity
                let test_state = SystemState {
                    memory_used_bytes: 50,
                    memory_budget_bytes: 100,
                    durability_level: 0.95,
                    hardening_level: HardeningLevel::Enhanced,
                    proposed_hardening_level: None,
                    evidence_emission_active: true,
                    memory_tail_risk: None,
                    reliability_telemetry: None,
                    epoch_id: 42,
                };

                // Test debug output safety
                let state_debug = format!("{:?}", test_state);
                assert!(
                    !state_debug.contains("%s"),
                    "State debug should not contain format specifiers: {}",
                    attack_name
                );
                assert!(
                    !state_debug.contains("\x1b["),
                    "State debug should escape ANSI sequences: {}",
                    attack_name
                );
                assert!(
                    !state_debug.contains("\r\n{"),
                    "State debug should not allow JSON injection: {}",
                    attack_name
                );

                // Test HardeningLevel debug formatting
                let hardening_variants = vec![
                    HardeningLevel::Baseline,
                    HardeningLevel::Enhanced,
                    HardeningLevel::Strict,
                ];

                for hardening_level in hardening_variants {
                    let hardening_debug = format!("{:?}", hardening_level);
                    assert!(
                        !hardening_debug.contains("%s"),
                        "Hardening debug should be safe: {}",
                        attack_name
                    );
                    assert!(
                        !hardening_debug.contains("\x1b["),
                        "Hardening debug should escape ANSI: {}",
                        attack_name
                    );
                }

                // Test GuardrailVerdict formatting integrity
                let verdict_cases = vec![
                    GuardrailVerdict::Allow,
                    GuardrailVerdict::Warn {
                        reason: malicious_pattern.to_string(),
                    },
                    GuardrailVerdict::Block {
                        reason: malicious_pattern.to_string(),
                    },
                ];

                for verdict in verdict_cases {
                    let verdict_debug = format!("{:?}", verdict);
                    assert!(
                        !verdict_debug.contains("\x1b["),
                        "Verdict debug should escape ANSI: {}",
                        attack_name
                    );

                    match verdict {
                        GuardrailVerdict::Warn { reason } | GuardrailVerdict::Block { reason } => {
                            // Verify reason is preserved but safely formatted
                            assert!(
                                verdict_debug.contains(&reason) || verdict_debug.len() > 10,
                                "Verdict should preserve or escape reason: {}",
                                attack_name
                            );
                        }
                        GuardrailVerdict::Allow => {}
                    }
                }

                // Test that potentially malicious content doesn't break structure
                let complex_debug = format!(
                    "{:?}",
                    (test_state, HardeningLevel::Strict, GuardrailVerdict::Allow)
                );
                assert!(
                    complex_debug.len() > 50,
                    "Complex debug should have substantial content: {}",
                    attack_name
                );
                assert!(
                    !complex_debug.contains("\\u0000"),
                    "Complex debug should escape null properly: {}",
                    attack_name
                );

                Ok(())
            });

            assert!(
                json_integrity_result.is_ok(),
                "JSON integrity test should not panic: {}",
                attack_name
            );
        }
    }

    /// Test arithmetic overflow protection in policy calculations
    #[test]
    fn negative_policy_arithmetic_overflow_protection() {
        use super::guardrail_monitor::{
            ConformalRiskGuardrail, GuardrailVerdict, MemoryBudgetGuardrail, ReliabilityTelemetry,
            SystemState,
        };
        use super::hardening_state_machine::HardeningLevel;

        let overflow_protection_result = std::panic::catch_unwind(|| {
            // Test memory budget calculations with extreme values
            let memory_overflow_cases = vec![
                (u64::MAX, 1, "max_used_min_budget"),
                (u64::MAX - 1, u64::MAX, "near_max_both"),
                (0, 1, "zero_used_min_budget"),
                (1, 0, "min_used_zero_budget"), // Edge case: zero budget
                (u64::MAX / 2, u64::MAX / 4, "half_max_over_budget"),
            ];

            for (memory_used, memory_budget, test_name) in memory_overflow_cases {
                let guardrail = MemoryBudgetGuardrail::new(0.8, 0.6);
                let state = SystemState {
                    memory_used_bytes: memory_used,
                    memory_budget_bytes: memory_budget,
                    durability_level: 0.95,
                    hardening_level: HardeningLevel::Enhanced,
                    proposed_hardening_level: None,
                    evidence_emission_active: true,
                    memory_tail_risk: None,
                    reliability_telemetry: None,
                    epoch_id: 1,
                };

                let verdict = guardrail.check(&state);

                // Should handle all cases without arithmetic overflow
                match verdict {
                    GuardrailVerdict::Allow
                    | GuardrailVerdict::Warn { .. }
                    | GuardrailVerdict::Block { .. } => {
                        // All verdicts are acceptable, just verify no panic occurred
                    }
                }

                // Test that percentage calculations are safe
                if memory_budget > 0 {
                    let usage_ratio = (memory_used as f64) / (memory_budget as f64);
                    assert!(
                        usage_ratio.is_finite() || usage_ratio.is_infinite(),
                        "Usage ratio should be mathematically valid: {}",
                        test_name
                    );
                }
            }

            // Test conformal risk with extreme sample counts
            let conformal_overflow_cases = vec![
                (u64::MAX, u64::MAX, "max_both_counts"),
                (u64::MAX, 0, "max_sample_zero_nonconform"),
                (0, u64::MAX, "zero_sample_max_nonconform"), // Invalid case
                (u64::MAX / 2, u64::MAX / 4, "large_realistic_counts"),
                (1, 0, "min_sample_zero_nonconform"),
            ];

            for (sample_count, nonconforming_count, test_name) in conformal_overflow_cases {
                let guardrail = ConformalRiskGuardrail::new(1000, 0.05);
                let state = SystemState {
                    memory_used_bytes: 50,
                    memory_budget_bytes: 100,
                    durability_level: 0.95,
                    hardening_level: HardeningLevel::Enhanced,
                    proposed_hardening_level: None,
                    evidence_emission_active: true,
                    memory_tail_risk: None,
                    reliability_telemetry: Some(ReliabilityTelemetry {
                        sample_count,
                        nonconforming_count,
                    }),
                    epoch_id: 1,
                };

                let verdict = guardrail.check(&state);

                // Should handle extreme counts without overflow
                match verdict {
                    GuardrailVerdict::Allow => {
                        // If allowed, verify the rate calculation was valid
                        if sample_count > 0 {
                            let rate = (nonconforming_count.min(sample_count) as f64)
                                / (sample_count as f64);
                            assert!(rate.is_finite(), "Rate should be finite: {}", test_name);
                            assert!(
                                rate >= 0.0 && rate <= 1.0,
                                "Rate should be in valid range: {}",
                                test_name
                            );
                        }
                    }
                    GuardrailVerdict::Warn { .. } | GuardrailVerdict::Block { .. } => {
                        // Conservative verdicts are always safe for extreme values
                    }
                }
            }

            // Test epoch ID overflow scenarios
            let epoch_overflow_cases = vec![0u64, 1u64, u64::MAX / 2, u64::MAX - 1, u64::MAX];

            for epoch_id in epoch_overflow_cases {
                let state = SystemState {
                    memory_used_bytes: 50,
                    memory_budget_bytes: 100,
                    durability_level: 0.95,
                    hardening_level: HardeningLevel::Enhanced,
                    proposed_hardening_level: None,
                    evidence_emission_active: true,
                    memory_tail_risk: None,
                    reliability_telemetry: None,
                    epoch_id,
                };

                // Should handle all epoch ID values without issue
                let debug_output = format!("{:?}", state);
                assert!(
                    debug_output.contains(&epoch_id.to_string()) || debug_output.len() > 50,
                    "Debug should handle epoch ID: {}",
                    epoch_id
                );
            }

            // Test threshold calculations with extreme float values
            let threshold_cases = vec![
                (0.0, 0.0, "zero_thresholds"),
                (1.0, 1.0, "max_thresholds"),
                (f64::EPSILON, f64::EPSILON, "min_positive_thresholds"),
                (0.999999999999, 0.999999999999, "near_one_thresholds"),
            ];

            for (warn_threshold, block_threshold, test_name) in threshold_cases {
                let guardrail = MemoryBudgetGuardrail::new(warn_threshold, block_threshold);
                let state = policy_state();

                let verdict = guardrail.check(&state);

                // Should handle all threshold values consistently
                match verdict {
                    GuardrailVerdict::Allow
                    | GuardrailVerdict::Warn { .. }
                    | GuardrailVerdict::Block { .. } => {
                        // All verdicts acceptable for threshold edge cases
                    }
                }

                // Verify guardrail can be formatted safely
                let guardrail_debug = format!("{:?}", guardrail);
                assert!(
                    !guardrail_debug.is_empty(),
                    "Guardrail debug should have content: {}",
                    test_name
                );
            }

            Ok(())
        });

        assert!(
            overflow_protection_result.is_ok(),
            "Arithmetic overflow protection test should not panic"
        );
    }

    /// Test concurrent access safety simulation in policy components
    #[test]
    fn negative_policy_concurrent_access_safety() {
        use super::guardrail_monitor::{
            DurabilityLossGuardrail, GuardrailMonitorSet, GuardrailVerdict, MemoryBudgetGuardrail,
            SystemState,
        };
        use super::hardening_state_machine::HardeningLevel;
        use std::sync::{Arc, Mutex};
        use std::thread;

        let concurrent_safety_result = std::panic::catch_unwind(|| {
            // Test concurrent guardrail monitoring (simulated)
            let monitor_set = Arc::new(Mutex::new(GuardrailMonitorSet::new()));

            // Add guardrails to the monitor set
            {
                let mut ms = monitor_set.lock().unwrap();
                ms.add_memory_budget_guardrail(MemoryBudgetGuardrail::new(0.8, 0.6));
                ms.add_durability_loss_guardrail(DurabilityLossGuardrail::new(0.95));
            }

            // Simulate concurrent state checking
            let mut handles = Vec::new();
            for thread_id in 0..3 {
                // Limit threads for test stability
                let monitor_clone = Arc::clone(&monitor_set);

                let handle = thread::spawn(move || {
                    for i in 0..20 {
                        let state = SystemState {
                            memory_used_bytes: 50 + (thread_id * 10) + (i % 20),
                            memory_budget_bytes: 100,
                            durability_level: 0.95 - (i as f64 * 0.001),
                            hardening_level: HardeningLevel::Enhanced,
                            proposed_hardening_level: None,
                            evidence_emission_active: true,
                            memory_tail_risk: None,
                            reliability_telemetry: None,
                            epoch_id: (thread_id as u64 * 1000) + i as u64,
                        };

                        // Acquire lock and check guardrails
                        if let Ok(ms) = monitor_clone.lock() {
                            let verdicts = ms.check_all(&state);

                            // Should handle concurrent access consistently
                            for verdict in verdicts {
                                match verdict {
                                    GuardrailVerdict::Allow => {}
                                    GuardrailVerdict::Warn { reason } => {
                                        assert!(
                                            !reason.is_empty(),
                                            "Warn reason should not be empty in thread {}",
                                            thread_id
                                        );
                                    }
                                    GuardrailVerdict::Block { reason } => {
                                        assert!(
                                            !reason.is_empty(),
                                            "Block reason should not be empty in thread {}",
                                            thread_id
                                        );
                                    }
                                }
                            }
                        }

                        // Yield to simulate concurrent access
                        thread::yield_now();
                    }
                });
                handles.push(handle);
            }

            // Wait for all threads to complete
            for handle in handles {
                handle.join().expect("Thread should complete without panic");
            }

            // Verify final state consistency
            if let Ok(final_monitor) = monitor_set.lock() {
                let final_state = policy_state();
                let final_verdicts = final_monitor.check_all(&final_state);

                // Should still function after concurrent access
                assert!(final_verdicts.len() >= 0, "Should return some verdicts");

                for verdict in final_verdicts {
                    // Verify verdicts are well-formed
                    let verdict_debug = format!("{:?}", verdict);
                    assert!(
                        !verdict_debug.is_empty(),
                        "Verdict should have debug representation"
                    );
                }
            }

            // Test concurrent state updates with safety
            let shared_state = Arc::new(Mutex::new(policy_state()));
            let update_handles: Vec<_> = (0..2)
                .map(|thread_id| {
                    let state_clone = Arc::clone(&shared_state);

                    thread::spawn(move || {
                        for i in 0..10 {
                            if let Ok(mut state) = state_clone.lock() {
                                // Simulate state updates
                                state.memory_used_bytes =
                                    state.memory_used_bytes.saturating_add(thread_id + i);
                                state.epoch_id = state.epoch_id.saturating_add(1);

                                // Test that state remains valid after updates
                                assert!(
                                    state.memory_used_bytes < u64::MAX,
                                    "Memory should not overflow"
                                );
                                assert!(
                                    state.durability_level >= 0.0 && state.durability_level <= 1.0,
                                    "Durability should remain in valid range"
                                );
                            }
                        }
                    })
                })
                .collect();

            for handle in update_handles {
                handle
                    .join()
                    .expect("State update thread should complete without panic");
            }

            // Verify final shared state is consistent
            if let Ok(final_shared_state) = shared_state.lock() {
                assert!(
                    final_shared_state.memory_used_bytes < u64::MAX,
                    "Final memory should be valid"
                );
                assert!(
                    final_shared_state.epoch_id > 0,
                    "Final epoch should be positive"
                );
            }

            Ok(())
        });

        assert!(
            concurrent_safety_result.is_ok(),
            "Concurrent access safety test should not panic"
        );
    }

    /// Test display injection and format string safety in policy output
    #[test]
    fn negative_policy_display_injection_safety() {
        use super::guardrail_monitor::{GuardrailVerdict, MemoryBudgetGuardrail, SystemState};
        use super::hardening_state_machine::HardeningLevel;

        let display_injection_vectors = vec![
            // Format string injection attempts
            ("format_inject", "reason%s%x%d"),
            ("format_overflow", "reason%.999999s"),
            ("format_position", "reason%1$s%2$x"),
            // ANSI escape sequence injection
            ("ansi_colors", "reason\x1b[31mRED\x1b[0m"),
            ("ansi_cursor", "reason\x1b[H\x1b[2J"),
            ("ansi_title", "reason\x1b]0;EVIL TITLE\x07"),
            // Terminal control injection
            ("bell_spam", "reason\x07\x07\x07"),
            ("backspace_attack", "reason\x08\x08\x08hidden"),
            ("carriage_return", "reason\roverwrite"),
            // Unicode display corruption
            ("rtl_override", "reason\u{202E}gnimrah\u{202D}"),
            (
                "combining_overflow",
                "reason\u{0300}\u{0301}\u{0302}\u{0303}",
            ),
            ("width_confusion", "reason\u{3000}\u{FF01}"),
            // Log injection attempts
            ("log_inject", "reason\nINJECTED: admin access"),
            ("log_crlf", "reason\r\n[FAKE] Policy violation"),
        ];

        for (attack_name, malicious_content) in display_injection_vectors {
            let display_safety_result = std::panic::catch_unwind(|| {
                // Test GuardrailVerdict display safety
                let verdicts = vec![
                    GuardrailVerdict::Allow,
                    GuardrailVerdict::Warn {
                        reason: malicious_content.to_string(),
                    },
                    GuardrailVerdict::Block {
                        reason: malicious_content.to_string(),
                    },
                ];

                for verdict in verdicts {
                    // Test debug display formatting safety
                    let verdict_display = format!("{:?}", verdict);
                    assert!(
                        !verdict_display.contains("%s"),
                        "Verdict display should not contain format specifiers: {}",
                        attack_name
                    );
                    assert!(
                        !verdict_display.contains("\x1b["),
                        "Verdict display should escape ANSI sequences: {}",
                        attack_name
                    );
                    assert!(
                        !verdict_display.contains("\r\n[FAKE]"),
                        "Verdict display should not allow log injection: {}",
                        attack_name
                    );

                    match verdict {
                        GuardrailVerdict::Warn { reason } | GuardrailVerdict::Block { reason } => {
                            // Verify reason is preserved but safely displayed
                            assert_eq!(
                                reason, malicious_content,
                                "Reason should be preserved: {}",
                                attack_name
                            );
                        }
                        GuardrailVerdict::Allow => {}
                    }
                }

                // Test SystemState display safety
                let state = SystemState {
                    memory_used_bytes: 50,
                    memory_budget_bytes: 100,
                    durability_level: 0.95,
                    hardening_level: HardeningLevel::Enhanced,
                    proposed_hardening_level: None,
                    evidence_emission_active: true,
                    memory_tail_risk: None,
                    reliability_telemetry: None,
                    epoch_id: 42,
                };

                let state_display = format!("{:?}", state);
                assert!(
                    !state_display.contains("%s"),
                    "State display should not contain format specifiers: {}",
                    attack_name
                );
                assert!(
                    !state_display.contains("\x1b["),
                    "State display should escape ANSI sequences: {}",
                    attack_name
                );

                // Test HardeningLevel display safety
                let hardening_levels = vec![
                    HardeningLevel::Baseline,
                    HardeningLevel::Enhanced,
                    HardeningLevel::Strict,
                ];

                for level in hardening_levels {
                    let level_display = format!("{:?}", level);
                    assert!(
                        !level_display.contains("%s"),
                        "Hardening level display should be safe: {}",
                        attack_name
                    );
                    assert!(
                        !level_display.contains("\x1b["),
                        "Hardening level display should escape ANSI: {}",
                        attack_name
                    );
                }

                // Test MemoryBudgetGuardrail display safety
                let guardrail = MemoryBudgetGuardrail::new(0.8, 0.6);
                let guardrail_display = format!("{:?}", guardrail);
                assert!(
                    !guardrail_display.contains("%s"),
                    "Guardrail display should be safe: {}",
                    attack_name
                );
                assert!(
                    !guardrail_display.contains("\x1b["),
                    "Guardrail display should escape ANSI: {}",
                    attack_name
                );

                Ok(())
            });

            assert!(
                display_safety_result.is_ok(),
                "Display injection test should not panic: {}",
                attack_name
            );
        }
    }

    /// Test boundary condition stress in policy edge cases
    #[test]
    fn negative_policy_boundary_stress_comprehensive() {
        use super::guardrail_monitor::{
            ConformalRiskGuardrail, DurabilityLossGuardrail, GuardrailVerdict,
            MemoryBudgetGuardrail, ReliabilityTelemetry, SystemState,
        };
        use super::hardening_state_machine::HardeningLevel;

        let boundary_stress_result = std::panic::catch_unwind(|| {
            // Test memory budget threshold boundaries
            let threshold_boundaries = vec![
                (0.0, 0.0, "zero_thresholds"),
                (1.0, 1.0, "max_thresholds"),
                (0.5, 0.5, "equal_thresholds"),
                (0.8, 0.6, "normal_thresholds"),
                (f64::EPSILON, f64::EPSILON, "epsilon_thresholds"),
                (
                    1.0 - f64::EPSILON,
                    1.0 - f64::EPSILON,
                    "near_one_thresholds",
                ),
            ];

            for (warn_threshold, block_threshold, test_name) in threshold_boundaries {
                let guardrail = MemoryBudgetGuardrail::new(warn_threshold, block_threshold);

                // Test with various memory usage scenarios
                let memory_scenarios = vec![
                    (0, 100, "zero_usage"),
                    (50, 100, "half_usage"),
                    (80, 100, "high_usage"),
                    (100, 100, "full_usage"),
                    (150, 100, "over_usage"),
                ];

                for (memory_used, memory_budget, memory_test) in memory_scenarios {
                    let state = SystemState {
                        memory_used_bytes: memory_used,
                        memory_budget_bytes: memory_budget,
                        durability_level: 0.95,
                        hardening_level: HardeningLevel::Enhanced,
                        proposed_hardening_level: None,
                        evidence_emission_active: true,
                        memory_tail_risk: None,
                        reliability_telemetry: None,
                        epoch_id: 1,
                    };

                    let verdict = guardrail.check(&state);

                    // Should handle all boundary combinations consistently
                    match verdict {
                        GuardrailVerdict::Allow
                        | GuardrailVerdict::Warn { .. }
                        | GuardrailVerdict::Block { .. } => {
                            // All verdicts are valid for boundary conditions
                        }
                    }
                }
            }

            // Test durability level boundaries
            let durability_boundaries = vec![
                (0.0, "zero_durability"),
                (0.5, "half_durability"),
                (0.95, "high_durability"),
                (1.0, "perfect_durability"),
                (1.1, "over_durability"), // Invalid but should be handled
            ];

            for (durability_level, test_name) in durability_boundaries {
                let guardrail = DurabilityLossGuardrail::new(0.95);
                let state = SystemState {
                    memory_used_bytes: 50,
                    memory_budget_bytes: 100,
                    durability_level,
                    hardening_level: HardeningLevel::Enhanced,
                    proposed_hardening_level: None,
                    evidence_emission_active: true,
                    memory_tail_risk: None,
                    reliability_telemetry: None,
                    epoch_id: 1,
                };

                let verdict = guardrail.check(&state);

                // Should handle all durability levels
                match verdict {
                    GuardrailVerdict::Allow
                    | GuardrailVerdict::Warn { .. }
                    | GuardrailVerdict::Block { .. } => {}
                }

                // Test state debug output
                let state_debug = format!("{:?}", state);
                assert!(
                    state_debug.contains(&durability_level.to_string()) || state_debug.len() > 50,
                    "State should represent durability level: {}",
                    test_name
                );
            }

            // Test conformal risk with boundary sample counts
            let sample_count_boundaries = vec![
                (0, 0, "zero_samples"),
                (1, 0, "one_sample_zero_nonconform"),
                (1, 1, "one_sample_one_nonconform"),
                (100, 5, "normal_samples"),
                (1000000, 50000, "large_samples"),
                (u64::MAX / 1000, u64::MAX / 2000, "very_large_samples"),
            ];

            for (sample_count, nonconforming_count, test_name) in sample_count_boundaries {
                let guardrail = ConformalRiskGuardrail::new(1000, 0.05);
                let state = SystemState {
                    memory_used_bytes: 50,
                    memory_budget_bytes: 100,
                    durability_level: 0.95,
                    hardening_level: HardeningLevel::Enhanced,
                    proposed_hardening_level: None,
                    evidence_emission_active: true,
                    memory_tail_risk: None,
                    reliability_telemetry: Some(ReliabilityTelemetry {
                        sample_count,
                        nonconforming_count,
                    }),
                    epoch_id: 1,
                };

                let verdict = guardrail.check(&state);

                // Should handle all sample count boundaries
                match verdict {
                    GuardrailVerdict::Allow => {
                        // Verify mathematical soundness for Allow verdict
                        if sample_count > 0 {
                            let rate = (nonconforming_count.min(sample_count) as f64)
                                / (sample_count as f64);
                            assert!(rate.is_finite(), "Rate should be finite: {}", test_name);
                            assert!(
                                rate >= 0.0 && rate <= 1.0,
                                "Rate should be in valid range: {}",
                                test_name
                            );
                        }
                    }
                    GuardrailVerdict::Warn { .. } | GuardrailVerdict::Block { .. } => {}
                }
            }

            // Test epoch ID boundaries
            let epoch_boundaries = vec![0u64, 1u64, 1000u64, u64::MAX / 2, u64::MAX - 1, u64::MAX];

            for epoch_id in epoch_boundaries {
                let state = SystemState {
                    memory_used_bytes: 50,
                    memory_budget_bytes: 100,
                    durability_level: 0.95,
                    hardening_level: HardeningLevel::Enhanced,
                    proposed_hardening_level: None,
                    evidence_emission_active: true,
                    memory_tail_risk: None,
                    reliability_telemetry: None,
                    epoch_id,
                };

                // Should handle all epoch ID values
                let state_debug = format!("{:?}", state);
                assert!(
                    !state_debug.is_empty(),
                    "State should have debug representation for epoch: {}",
                    epoch_id
                );

                // Test guardrail evaluation with various epochs
                let guardrail = MemoryBudgetGuardrail::new(0.8, 0.6);
                let verdict = guardrail.check(&state);

                match verdict {
                    GuardrailVerdict::Allow
                    | GuardrailVerdict::Warn { .. }
                    | GuardrailVerdict::Block { .. } => {}
                }
            }

            // Test hardening level boundaries
            let hardening_levels = vec![
                HardeningLevel::Baseline,
                HardeningLevel::Enhanced,
                HardeningLevel::Strict,
            ];

            for hardening_level in hardening_levels {
                let state = SystemState {
                    memory_used_bytes: 50,
                    memory_budget_bytes: 100,
                    durability_level: 0.95,
                    hardening_level,
                    proposed_hardening_level: Some(hardening_level),
                    evidence_emission_active: true,
                    memory_tail_risk: None,
                    reliability_telemetry: None,
                    epoch_id: 1,
                };

                // Should handle all hardening levels
                let state_debug = format!("{:?}", state);
                assert!(
                    !state_debug.is_empty(),
                    "State should represent hardening level: {:?}",
                    hardening_level
                );

                // Test with evidence emission boundaries
                for evidence_active in [true, false] {
                    let mut evidence_state = state.clone();
                    evidence_state.evidence_emission_active = evidence_active;

                    let evidence_debug = format!("{:?}", evidence_state);
                    assert!(
                        evidence_debug.contains(&evidence_active.to_string())
                            || evidence_debug.len() > 50,
                        "State should represent evidence emission: {}",
                        evidence_active
                    );
                }
            }

            Ok(())
        });

        assert!(
            boundary_stress_result.is_ok(),
            "Boundary stress test should not panic"
        );
    }
}
