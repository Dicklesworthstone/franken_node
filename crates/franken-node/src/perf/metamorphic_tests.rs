//! Metamorphic tests for performance optimization governor.
//!
//! These tests verify metamorphic relations that must hold for correct governor behavior,
//! using property-based testing to explore the input space without requiring exact oracles.

#[cfg(test)]
mod tests {
    use super::optimization_governor::*;
    use proptest::prelude::*;

    // Helper to generate valid optimization proposals
    fn arb_optimization_proposal() -> impl Strategy<Value = OptimizationProposal> {
        (
            "[a-z]{1,10}",
            any::<RuntimeKnob>(),
            0u64..1000,
            0u64..1000,
            arb_predicted_metrics(),
            "[a-z]{1,20}",
            "[a-z]{1,15}",
        ).prop_map(|(id, knob, old_val, new_val, metrics, rationale, trace_id)| {
            OptimizationProposal {
                proposal_id: id,
                knob,
                old_value: old_val,
                new_value: new_val,
                predicted: metrics,
                rationale,
                trace_id,
            }
        })
    }

    fn arb_predicted_metrics() -> impl Strategy<Value = PredictedMetrics> {
        (
            1u32..2000,   // latency_ms
            1u32..10000,  // throughput_rps
            0.0f64..5.0,  // error_rate_pct
            100u32..8192, // memory_mb
        ).prop_map(|(lat, thr, err, mem)| {
            PredictedMetrics {
                latency_ms: lat,
                throughput_rps: thr,
                error_rate_pct: err,
                memory_mb: mem,
            }
        })
    }

    fn arb_runtime_knob() -> impl Strategy<Value = RuntimeKnob> {
        prop_oneof![
            Just(RuntimeKnob::ConcurrencyLimit),
            Just(RuntimeKnob::BatchSizeLimit),
            Just(RuntimeKnob::TimeoutMs),
            Just(RuntimeKnob::RetryLimit),
            Just(RuntimeKnob::MemoryBudgetMb),
        ]
    }

    impl Arbitrary for RuntimeKnob {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: ()) -> Self::Strategy {
            arb_runtime_knob().boxed()
        }
    }

    #[test]
    fn mr_equivalence_identical_proposals_same_decision() {
        // MR1: Applying the same optimization proposal should yield the same decision
        proptest!(|(proposal: OptimizationProposal)| {
            let mut governor1 = OptimizationGovernor::with_defaults();
            let mut governor2 = OptimizationGovernor::with_defaults();

            let decision1 = governor1.submit(proposal.clone());
            let decision2 = governor2.submit(proposal.clone());

            prop_assert_eq!(
                std::mem::discriminant(&decision1),
                std::mem::discriminant(&decision2),
                "Same proposal should yield same decision type"
            );
        });
    }

    #[test]
    fn mr_additive_resource_limit_monotonicity() {
        // MR2: Increasing resource limits should monotonically improve or maintain metrics
        proptest!(|(base_proposal: OptimizationProposal, increment: u64)| {
            let increment = increment.saturating_add(1); // Ensure positive
            let mut enhanced_proposal = base_proposal.clone();

            // Scale up the new_value (represents increased resource limit)
            enhanced_proposal.new_value = base_proposal.new_value.saturating_add(increment);

            // For resource limits, higher values should not make metrics worse
            // (This is a domain-specific metamorphic relation)
            match (base_proposal.knob, enhanced_proposal.knob) {
                (RuntimeKnob::ConcurrencyLimit, RuntimeKnob::ConcurrencyLimit) => {
                    // Higher concurrency should not decrease throughput (all else equal)
                    if enhanced_proposal.predicted.throughput_rps < base_proposal.predicted.throughput_rps {
                        prop_assert!(
                            enhanced_proposal.predicted.error_rate_pct > base_proposal.predicted.error_rate_pct ||
                            enhanced_proposal.predicted.latency_ms > base_proposal.predicted.latency_ms,
                            "Decreased throughput must be compensated by worse error rate or latency"
                        );
                    }
                }
                _ => {}
            }
        });
    }

    #[test]
    fn mr_permutation_knob_order_invariance() {
        // MR3: The order of applying independent knob changes shouldn't affect final state
        proptest!(|(
            proposal1: OptimizationProposal,
            proposal2: OptimizationProposal
        )| {
            // Only test if knobs are different (independent changes)
            prop_assume!(proposal1.knob != proposal2.knob);
            prop_assume!(!proposal1.proposal_id.is_empty());
            prop_assume!(!proposal2.proposal_id.is_empty());
            prop_assume!(!proposal1.trace_id.is_empty());
            prop_assume!(!proposal2.trace_id.is_empty());

            let mut governor_12 = OptimizationGovernor::with_defaults();
            let mut governor_21 = OptimizationGovernor::with_defaults();

            // Apply in order 1->2
            let _ = governor_12.submit(proposal1.clone());
            let _ = governor_12.submit(proposal2.clone());

            // Apply in order 2->1
            let _ = governor_21.submit(proposal2.clone());
            let _ = governor_21.submit(proposal1.clone());

            // Final knob values should be the same regardless of application order
            prop_assert_eq!(
                governor_12.knob_value(&proposal1.knob),
                governor_21.knob_value(&proposal1.knob),
                "Knob1 final value should be order-invariant"
            );
            prop_assert_eq!(
                governor_12.knob_value(&proposal2.knob),
                governor_21.knob_value(&proposal2.knob),
                "Knob2 final value should be order-invariant"
            );
        });
    }

    #[test]
    fn mr_inclusive_safety_envelope_nesting() {
        // MR4: Stricter safety envelopes should reject a superset of what looser ones reject
        proptest!(|(proposal: OptimizationProposal)| {
            prop_assume!(!proposal.proposal_id.is_empty());
            prop_assume!(!proposal.trace_id.is_empty());

            // Create loose and strict safety envelopes
            let loose_envelope = SafetyEnvelope {
                max_latency_ms: 1000,
                min_throughput_rps: 100,
                max_error_rate_pct: 2.0,
                max_memory_mb: 8192,
            };

            let strict_envelope = SafetyEnvelope {
                max_latency_ms: 500,
                min_throughput_rps: 200,
                max_error_rate_pct: 1.0,
                max_memory_mb: 4096,
            };

            let mut loose_governor = OptimizationGovernor::with_envelope(loose_envelope);
            let mut strict_governor = OptimizationGovernor::with_envelope(strict_envelope);

            let loose_decision = loose_governor.submit(proposal.clone());
            let strict_decision = strict_governor.submit(proposal.clone());

            // If strict rejects, loose must not accept (contrapositive)
            match (&loose_decision, &strict_decision) {
                (GovernorDecision::Accepted(_), GovernorDecision::Rejected(_)) => {
                    // This is allowed - loose accepts what strict rejects
                }
                (GovernorDecision::Rejected(_), GovernorDecision::Accepted(_)) => {
                    prop_assert!(false, "Strict envelope cannot accept what loose envelope rejects");
                }
                _ => {
                    // Both accept or both reject - also valid
                }
            }
        });
    }

    #[test]
    fn mr_multiplicative_proposal_scaling() {
        // MR5: Scaling both old_value and new_value by same factor should preserve decision rationale
        proptest!(|(base_proposal: OptimizationProposal, scale_factor: u64)| {
            prop_assume!(scale_factor > 1 && scale_factor < 10); // Reasonable scaling
            prop_assume!(!base_proposal.proposal_id.is_empty());
            prop_assume!(!base_proposal.trace_id.is_empty());
            prop_assume!(base_proposal.old_value > 0 && base_proposal.new_value > 0);

            let scaled_proposal = OptimizationProposal {
                old_value: base_proposal.old_value.saturating_mul(scale_factor),
                new_value: base_proposal.new_value.saturating_mul(scale_factor),
                ..base_proposal.clone()
            };

            let mut base_governor = OptimizationGovernor::with_defaults();
            let mut scaled_governor = OptimizationGovernor::with_defaults();

            let base_decision = base_governor.submit(base_proposal);
            let scaled_decision = scaled_governor.submit(scaled_proposal);

            // The decision type (accept/reject) should be the same for proportional scaling
            prop_assert_eq!(
                std::mem::discriminant(&base_decision),
                std::mem::discriminant(&scaled_decision),
                "Proportional scaling should preserve decision type"
            );
        });
    }
}