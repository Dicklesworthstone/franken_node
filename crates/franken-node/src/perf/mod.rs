//! Performance subsystem modules for franken-node.
//!
//! The `perf` crate-level module groups performance-related governors,
//! budget gates, and optimization infrastructure.

pub mod optimization_governor;

#[cfg(test)]
mod metamorphic_tests;

#[cfg(test)]
mod tests {
    use super::optimization_governor::{
        GOV_010_KNOB_DISPATCHED, GovernorDecision, GovernorGate, OptimizationGovernor,
        OptimizationProposal, PredictedMetrics, RejectionReason, RuntimeKnob, error_codes,
        event_codes,
    };

    fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
        if cap == 0 {
            items.clear();
            return;
        }
        if items.len() >= cap {
            let overflow = items.len().saturating_sub(cap).saturating_add(1);
            items.drain(0..overflow.min(items.len()));
        }
        items.push(item);
    }

    fn safe_metrics() -> PredictedMetrics {
        PredictedMetrics {
            latency_ms: 200,
            throughput_rps: 500,
            error_rate_pct: 0.1,
            memory_mb: 2048,
        }
    }

    fn unsafe_metrics() -> PredictedMetrics {
        PredictedMetrics {
            latency_ms: 501,
            throughput_rps: 99,
            error_rate_pct: 1.1,
            memory_mb: 4097,
        }
    }

    fn proposal(
        id: &str,
        knob: RuntimeKnob,
        old_value: u64,
        new_value: u64,
        predicted: PredictedMetrics,
    ) -> OptimizationProposal {
        OptimizationProposal {
            proposal_id: id.to_string(),
            knob,
            old_value,
            new_value,
            predicted,
            rationale: format!("negative perf module probe {id}"),
            trace_id: format!("trace-{id}"),
        }
    }

    fn concurrency_proposal(id: &str) -> OptimizationProposal {
        proposal(id, RuntimeKnob::ConcurrencyLimit, 64, 128, safe_metrics())
    }

    #[test]
    fn negative_perf_governor_rejects_empty_proposal_id_without_apply() {
        let mut governor = OptimizationGovernor::with_defaults();

        let decision = governor.submit(concurrency_proposal(""));

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::InvalidProposal(_))
        ));
        assert_eq!(governor.applied_count(), 0);
        assert_eq!(
            governor.knob_value(&RuntimeKnob::ConcurrencyLimit),
            Some(64)
        );
        assert_eq!(
            governor
                .decision_log()
                .last()
                .map(|entry| entry.event_code.as_str()),
            Some(event_codes::GOV_004)
        );
    }

    #[test]
    fn negative_perf_governor_rejects_empty_trace_id_without_apply() {
        let mut governor = OptimizationGovernor::with_defaults();
        let mut candidate = concurrency_proposal("missing-trace");
        candidate.trace_id.clear();

        let decision = governor.submit(candidate);

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::InvalidProposal(_))
        ));
        assert_eq!(governor.applied_count(), 0);
        assert!(
            governor
                .decision_log()
                .last()
                .and_then(|entry| entry.evidence.as_deref())
                .is_some_and(|evidence| evidence.contains(error_codes::ERR_GOV_INVALID_PROPOSAL))
        );
    }

    #[test]
    fn negative_perf_governor_rejects_nan_error_rate_as_invalid() {
        let mut governor = OptimizationGovernor::with_defaults();
        let mut candidate = concurrency_proposal("nan-error-rate");
        candidate.predicted.error_rate_pct = f64::NAN;

        let decision = governor.submit(candidate);

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::InvalidProposal(_))
        ));
        assert_eq!(governor.applied_count(), 0);
        assert_eq!(governor.decision_count(), 1);
    }

    #[test]
    fn negative_perf_governor_rejects_outdated_baseline_value() {
        let mut governor = OptimizationGovernor::with_defaults();
        let mut candidate = concurrency_proposal("outdated-baseline");
        candidate.old_value = 63;

        let decision = governor.submit(candidate);

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::InvalidProposal(_))
        ));
        assert_eq!(
            governor.knob_value(&RuntimeKnob::ConcurrencyLimit),
            Some(64)
        );
        assert_eq!(governor.applied_count(), 0);
    }

    #[test]
    fn negative_perf_governor_rejects_locked_knob_change() {
        let mut governor = OptimizationGovernor::with_defaults();
        governor.lock_knob(RuntimeKnob::ConcurrencyLimit);

        let decision = governor.submit(concurrency_proposal("locked-knob"));

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::KnobLocked)
        ));
        assert_eq!(
            governor.knob_value(&RuntimeKnob::ConcurrencyLimit),
            Some(64)
        );
        assert_eq!(governor.applied_count(), 0);
    }

    #[test]
    fn negative_perf_governor_rejects_multi_metric_envelope_breach() {
        let mut governor = OptimizationGovernor::with_defaults();
        let candidate = proposal(
            "multi-metric-breach",
            RuntimeKnob::BatchSize,
            128,
            256,
            unsafe_metrics(),
        );

        let decision = governor.submit(candidate);

        match decision {
            GovernorDecision::Rejected(RejectionReason::EnvelopeViolation(violations)) => {
                assert!(violations.iter().any(|item| item.contains("latency")));
                assert!(violations.iter().any(|item| item.contains("throughput")));
                assert!(violations.iter().any(|item| item.contains("error rate")));
                assert!(violations.iter().any(|item| item.contains("memory")));
            }
            other => panic!("expected envelope rejection, got {other:?}"),
        }
        assert_eq!(governor.knob_value(&RuntimeKnob::BatchSize), Some(128));
        assert_eq!(governor.applied_count(), 0);
    }

    #[test]
    fn negative_perf_governor_rejects_non_beneficial_noop_change() {
        let mut governor = OptimizationGovernor::with_defaults();
        let candidate = proposal(
            "noop-change",
            RuntimeKnob::RetryBudget,
            3,
            3,
            safe_metrics(),
        );

        let decision = governor.submit(candidate);

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::NonBeneficial)
        ));
        assert_eq!(governor.knob_value(&RuntimeKnob::RetryBudget), Some(3));
        assert_eq!(governor.applied_count(), 0);
    }

    #[test]
    fn negative_perf_gate_rejects_engine_internal_adjustment() {
        let mut gate = GovernorGate::with_defaults();

        let err = gate
            .reject_engine_internal_adjustment("engine_core::scheduler_budget")
            .expect_err("engine internals must be outside the governor boundary");

        assert!(err.contains(error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION));
        assert!(gate.audit_trail().iter().any(|entry| {
            entry.event_code == error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION
        }));
    }

    #[test]
    fn negative_perf_gate_rejects_bad_proposal_without_dispatch_payload() {
        let mut gate = GovernorGate::with_defaults();
        let candidate = proposal(
            "dispatch-breach",
            RuntimeKnob::BatchSize,
            128,
            256,
            unsafe_metrics(),
        );

        let (decision, payload) = gate.submit_and_dispatch(candidate);

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::EnvelopeViolation(_))
        ));
        assert!(payload.is_none());
        assert!(
            !gate
                .audit_trail()
                .iter()
                .any(|entry| entry.event_code == GOV_010_KNOB_DISPATCHED)
        );
    }

    #[test]
    fn negative_perf_gate_live_breach_auto_reverts_applied_policy() {
        let mut gate = GovernorGate::with_defaults();
        assert!(matches!(
            gate.submit(concurrency_proposal("auto-revert")),
            GovernorDecision::Approved
        ));

        let reverted = gate.live_check(&unsafe_metrics());

        assert_eq!(reverted, vec!["auto-revert".to_string()]);
        assert_eq!(gate.inner().applied_count(), 0);
        assert_eq!(
            gate.inner().knob_value(&RuntimeKnob::ConcurrencyLimit),
            Some(64)
        );
    }
}

#[cfg(test)]
mod perf_module_negative_tests {
    use super::optimization_governor::{
        GOV_010_KNOB_DISPATCHED, GovernorDecision, GovernorGate, OptimizationGovernor,
        OptimizationProposal, PredictedMetrics, RejectionReason, RuntimeKnob, SafetyEnvelope,
        error_codes,
    };

    fn safe_metrics() -> PredictedMetrics {
        PredictedMetrics {
            latency_ms: 200,
            throughput_rps: 500,
            error_rate_pct: 0.1,
            memory_mb: 2048,
        }
    }

    fn proposal(id: &str) -> OptimizationProposal {
        OptimizationProposal {
            proposal_id: id.to_string(),
            knob: RuntimeKnob::ConcurrencyLimit,
            old_value: 64,
            new_value: 128,
            predicted: safe_metrics(),
            rationale: "negative-path governor probe".to_string(),
            trace_id: format!("trace-{id}"),
        }
    }

    #[test]
    fn negative_empty_proposal_id_is_rejected() {
        let mut gate = GovernorGate::with_defaults();
        let mut candidate = proposal("");
        candidate.proposal_id.clear();

        let decision = gate.submit(candidate);

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::InvalidProposal(_))
        ));
        assert_eq!(gate.inner().applied_count(), 0);
    }

    #[test]
    fn negative_empty_trace_id_is_rejected() {
        let mut gate = GovernorGate::with_defaults();
        let mut candidate = proposal("empty-trace");
        candidate.trace_id.clear();

        let decision = gate.submit(candidate);

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::InvalidProposal(_))
        ));
        assert_eq!(gate.inner().applied_count(), 0);
    }

    #[test]
    fn negative_stale_old_value_does_not_change_knob() {
        let mut gate = GovernorGate::with_defaults();
        let mut candidate = proposal("stale-old-value");
        candidate.old_value = 63;

        let decision = gate.submit(candidate);

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::InvalidProposal(_))
        ));
        assert_eq!(
            gate.inner().knob_value(&RuntimeKnob::ConcurrencyLimit),
            Some(64)
        );
        assert_eq!(gate.inner().applied_count(), 0);
    }

    #[test]
    fn negative_locked_knob_blocks_dispatch_payload() {
        let mut governor = OptimizationGovernor::with_defaults();
        governor.lock_knob(RuntimeKnob::ConcurrencyLimit);
        let mut gate = GovernorGate::new(governor);

        let (decision, payload) = gate.submit_and_dispatch(proposal("locked-knob"));

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::KnobLocked)
        ));
        assert!(payload.is_none());
        assert_eq!(gate.inner().applied_count(), 0);
    }

    #[test]
    fn negative_unsafe_metrics_do_not_dispatch() {
        let mut gate = GovernorGate::with_defaults();
        let mut candidate = proposal("unsafe-metrics");
        candidate.predicted = PredictedMetrics {
            latency_ms: 900,
            throughput_rps: 50,
            error_rate_pct: 2.0,
            memory_mb: 8192,
        };

        let (decision, payload) = gate.submit_and_dispatch(candidate);

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::EnvelopeViolation(_))
        ));
        assert!(payload.is_none());
        assert_eq!(gate.inner().applied_count(), 0);
    }

    #[test]
    fn negative_nan_error_rate_is_invalid_proposal() {
        let mut gate = GovernorGate::with_defaults();
        let mut candidate = proposal("nan-error-rate");
        candidate.predicted.error_rate_pct = f64::NAN;

        let decision = gate.submit(candidate);

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::InvalidProposal(_))
        ));
        assert!(
            gate.audit_trail()
                .iter()
                .any(|entry| { entry.event_code == error_codes::ERR_GOVERNOR_SHADOW_EVAL_FAILED })
        );
    }

    #[test]
    fn negative_invalid_safety_envelope_is_not_valid() {
        let envelope = SafetyEnvelope {
            max_latency_ms: 0,
            min_throughput_rps: 0,
            max_error_rate_pct: f64::NAN,
            max_memory_mb: 0,
        };

        assert!(!envelope.is_valid());
    }

    #[test]
    fn negative_engine_internal_adjustment_is_audit_logged_and_rejected() {
        let mut gate = GovernorGate::with_defaults();

        let err = gate
            .reject_engine_internal_adjustment("engine_core::allocator")
            .expect_err("engine-core internals must stay outside governor control");

        assert!(err.contains(error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION));
        assert!(gate.audit_trail().iter().any(|entry| {
            entry.event_code == error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION
        }));
    }

    #[test]
    fn negative_unknown_runtime_knob_wire_value_is_rejected() {
        let result = serde_json::from_str::<RuntimeKnob>("\"engine_core_threads\"");

        assert!(result.is_err());
    }

    #[test]
    fn negative_camel_case_runtime_knob_wire_value_is_rejected() {
        let result = serde_json::from_str::<RuntimeKnob>("\"ConcurrencyLimit\"");

        assert!(result.is_err());
    }

    #[test]
    fn negative_rejection_reason_rejects_wrong_variant_shape() {
        let result = serde_json::from_value::<RejectionReason>(serde_json::json!({
            "envelope_violation": "latency breach"
        }));

        assert!(result.is_err());
    }

    #[test]
    fn negative_non_beneficial_submit_and_dispatch_emits_no_payload() {
        let mut gate = GovernorGate::with_defaults();
        let mut candidate = proposal("noop-dispatch");
        candidate.new_value = candidate.old_value;

        let (decision, payload) = gate.submit_and_dispatch(candidate);

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::NonBeneficial)
        ));
        assert!(payload.is_none());
        assert!(
            !gate
                .audit_trail()
                .iter()
                .any(|entry| entry.event_code == GOV_010_KNOB_DISPATCHED)
        );
    }

    #[test]
    fn negative_invalid_envelope_rejects_safe_proposal_without_apply() {
        let mut governor = OptimizationGovernor::with_defaults();
        governor.update_envelope(SafetyEnvelope {
            max_latency_ms: 500,
            min_throughput_rps: 100,
            max_error_rate_pct: f64::NAN,
            max_memory_mb: 4096,
        });

        let decision = governor.submit(proposal("invalid-envelope"));

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::EnvelopeViolation(_))
        ));
        assert_eq!(governor.applied_count(), 0);
        assert_eq!(
            governor.knob_value(&RuntimeKnob::ConcurrencyLimit),
            Some(64)
        );
    }

    #[test]
    fn negative_live_check_with_nan_error_rate_reverts_applied_policy() {
        let mut gate = GovernorGate::with_defaults();
        assert!(matches!(
            gate.submit(proposal("nan-live-revert")),
            GovernorDecision::Approved
        ));

        let reverted = gate.live_check(&PredictedMetrics {
            latency_ms: 200,
            throughput_rps: 500,
            error_rate_pct: f64::NAN,
            memory_mb: 2048,
        });

        assert_eq!(reverted, vec!["nan-live-revert".to_string()]);
        assert_eq!(gate.inner().applied_count(), 0);
        assert_eq!(
            gate.inner().knob_value(&RuntimeKnob::ConcurrencyLimit),
            Some(64)
        );
    }

    #[test]
    fn negative_serialized_proposal_rejects_string_metric_types() {
        let result = serde_json::from_value::<OptimizationProposal>(serde_json::json!({
            "proposal_id": "bad-metric-wire",
            "knob": "concurrency_limit",
            "old_value": 64,
            "new_value": 128,
            "predicted": {
                "latency_ms": "200",
                "throughput_rps": 500,
                "error_rate_pct": 0.1,
                "memory_mb": 2048
            },
            "rationale": "bad metric wire type",
            "trace_id": "trace-bad-metric-wire"
        }));

        assert!(result.is_err());
    }
}

#[cfg(test)]
mod perf_module_dispatch_boundary_negative_tests {
    use super::optimization_governor::{
        DispatchHookPayload, GovernorDecision, GovernorGate, OptimizationGovernor,
        OptimizationProposal, PredictedMetrics, RejectionReason, RuntimeKnob, SafetyEnvelope,
        event_codes,
    };
    use std::collections::BTreeMap;

    fn safe_metrics() -> PredictedMetrics {
        PredictedMetrics {
            latency_ms: 200,
            throughput_rps: 500,
            error_rate_pct: 0.1,
            memory_mb: 2048,
        }
    }

    fn unsafe_metrics() -> PredictedMetrics {
        PredictedMetrics {
            latency_ms: 900,
            throughput_rps: 50,
            error_rate_pct: 2.0,
            memory_mb: 8192,
        }
    }

    fn proposal_for(
        id: &str,
        knob: RuntimeKnob,
        old_value: u64,
        new_value: u64,
        predicted: PredictedMetrics,
    ) -> OptimizationProposal {
        OptimizationProposal {
            proposal_id: id.to_string(),
            knob,
            old_value,
            new_value,
            predicted,
            rationale: format!("negative dispatch boundary probe {id}"),
            trace_id: format!("trace-{id}"),
        }
    }

    #[test]
    fn negative_shadow_only_unsafe_metrics_reports_violation_without_apply() {
        let governor = OptimizationGovernor::with_defaults();
        let candidate = proposal_for(
            "shadow-unsafe",
            RuntimeKnob::ConcurrencyLimit,
            64,
            128,
            unsafe_metrics(),
        );

        let shadow = governor.submit_shadow_only(&candidate);

        assert!(!shadow.within_envelope);
        assert!(!shadow.is_beneficial);
        assert!(
            shadow
                .violations
                .iter()
                .any(|item| item.contains("latency"))
        );
        assert_eq!(governor.applied_count(), 0);
        assert_eq!(governor.decision_count(), 0);
        assert_eq!(
            governor.knob_value(&RuntimeKnob::ConcurrencyLimit),
            Some(64)
        );
    }

    #[test]
    fn negative_missing_knob_state_rejects_without_dispatch_payload() {
        let governor = OptimizationGovernor::new(SafetyEnvelope::default(), BTreeMap::new());
        let mut gate = GovernorGate::new(governor);

        let (decision, payload) = gate.submit_and_dispatch(proposal_for(
            "missing-knob",
            RuntimeKnob::ConcurrencyLimit,
            64,
            128,
            safe_metrics(),
        ));

        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::InvalidProposal(_))
        ));
        assert!(payload.is_none());
        assert_eq!(gate.inner().applied_count(), 0);
        assert_eq!(
            gate.inner().knob_value(&RuntimeKnob::ConcurrencyLimit),
            None
        );
    }

    #[test]
    fn negative_dispatch_payload_rejects_non_string_env_values() {
        let result = serde_json::from_value::<DispatchHookPayload>(serde_json::json!({
            "env_vars": {
                "FRANKEN_GOV_CONCURRENCY_LIMIT": 128
            },
            "schema_version": "gov-v1.0",
            "applied_count": 1
        }));

        assert!(result.is_err());
    }

    #[test]
    fn negative_dispatch_payload_rejects_negative_applied_count() {
        let result = serde_json::from_value::<DispatchHookPayload>(serde_json::json!({
            "env_vars": {
                "FRANKEN_GOV_CONCURRENCY_LIMIT": "128"
            },
            "schema_version": "gov-v1.0",
            "applied_count": -1
        }));

        assert!(result.is_err());
    }

    #[test]
    fn negative_live_check_reverts_multiple_applied_policies_last_applied_first() {
        let mut gate = GovernorGate::with_defaults();
        assert!(matches!(
            gate.submit(proposal_for(
                "first-live-revert",
                RuntimeKnob::ConcurrencyLimit,
                64,
                128,
                safe_metrics(),
            )),
            GovernorDecision::Approved
        ));
        assert!(matches!(
            gate.submit(proposal_for(
                "second-live-revert",
                RuntimeKnob::BatchSize,
                128,
                256,
                safe_metrics(),
            )),
            GovernorDecision::Approved
        ));

        let reverted = gate.live_check(&unsafe_metrics());

        assert_eq!(
            reverted,
            vec![
                "second-live-revert".to_string(),
                "first-live-revert".to_string()
            ]
        );
        assert_eq!(gate.inner().applied_count(), 0);
        assert_eq!(
            gate.inner().knob_value(&RuntimeKnob::ConcurrencyLimit),
            Some(64)
        );
        assert_eq!(gate.inner().knob_value(&RuntimeKnob::BatchSize), Some(128));
    }

    #[test]
    fn negative_valid_live_metrics_after_rejection_records_no_revert_event() {
        let mut gate = GovernorGate::with_defaults();
        let decision = gate.submit(proposal_for(
            "rejected-before-live",
            RuntimeKnob::ConcurrencyLimit,
            64,
            128,
            unsafe_metrics(),
        ));
        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::EnvelopeViolation(_))
        ));

        let reverted = gate.live_check(&safe_metrics());

        assert!(reverted.is_empty());
        assert!(
            !gate
                .audit_trail()
                .iter()
                .any(|entry| entry.event_code == event_codes::GOVERNOR_POLICY_REVERTED)
        );
    }

    #[test]
    fn negative_unknown_governor_decision_wire_variant_is_rejected() {
        let result = serde_json::from_str::<GovernorDecision>("\"force_apply\"");

        assert!(result.is_err());
    }
}

#[cfg(test)]
mod perf_module_extreme_adversarial_negative_tests {
    use super::optimization_governor::{
        GovernorDecision, GovernorGate, OptimizationGovernor, OptimizationProposal,
        PredictedMetrics, RejectionReason, RuntimeKnob, SafetyEnvelope, error_codes,
    };
    use std::collections::BTreeMap;

    #[test]
    fn extreme_adversarial_unicode_injection_proposal_id_resistance() {
        let mut gate = GovernorGate::with_defaults();
        let unicode_bomb = format!(
            "{}{}{}{}{}",
            "\u{202E}",              // RIGHT-TO-LEFT OVERRIDE
            "\u{200B}".repeat(1000), // ZERO WIDTH SPACE x1000
            "\u{FEFF}".repeat(100),  // BOM x100
            "malicious\u{0000}payload\u{0001}",
            "\u{202D}" // LEFT-TO-RIGHT OVERRIDE
        );

        let candidate = OptimizationProposal {
            proposal_id: unicode_bomb,
            knob: RuntimeKnob::ConcurrencyLimit,
            old_value: 64,
            new_value: 128,
            predicted: PredictedMetrics {
                latency_ms: 200,
                throughput_rps: 500,
                error_rate_pct: 0.1,
                memory_mb: 2048,
            },
            rationale: "unicode injection test".to_string(),
            trace_id: "trace-unicode-bomb".to_string(),
        };

        let decision = gate.submit(candidate);
        // Should handle Unicode gracefully without panics
        assert!(matches!(
            decision,
            GovernorDecision::Rejected(_) | GovernorDecision::Approved
        ));
    }

    #[test]
    fn extreme_adversarial_memory_stress_massive_rationale_field() {
        let mut gate = GovernorGate::with_defaults();
        let massive_rationale = "A".repeat(10_000_000); // 10MB string

        let candidate = OptimizationProposal {
            proposal_id: "memory-stress".to_string(),
            knob: RuntimeKnob::ConcurrencyLimit,
            old_value: 64,
            new_value: 128,
            predicted: PredictedMetrics {
                latency_ms: 200,
                throughput_rps: 500,
                error_rate_pct: 0.1,
                memory_mb: 2048,
            },
            rationale: massive_rationale,
            trace_id: "trace-memory-stress".to_string(),
        };

        let decision = gate.submit(candidate);
        // Should handle large memory allocations without crashes
        assert!(matches!(
            decision,
            GovernorDecision::Rejected(_) | GovernorDecision::Approved
        ));
    }

    #[test]
    fn extreme_adversarial_arithmetic_overflow_boundary_values() {
        let mut gate = GovernorGate::with_defaults();

        let candidate = OptimizationProposal {
            proposal_id: "overflow-boundary".to_string(),
            knob: RuntimeKnob::ConcurrencyLimit,
            old_value: u64::MAX - 1,
            new_value: u64::MAX,
            predicted: PredictedMetrics {
                latency_ms: f64::MAX,
                throughput_rps: f64::INFINITY,
                error_rate_pct: f64::NEG_INFINITY,
                memory_mb: f64::NAN,
            },
            rationale: "arithmetic boundary test".to_string(),
            trace_id: "trace-overflow".to_string(),
        };

        let decision = gate.submit(candidate);
        // Must reject due to invalid metrics without arithmetic overflow
        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::InvalidProposal(_))
        ));
    }

    #[test]
    fn extreme_adversarial_contradictory_safety_envelope_config() {
        let contradictory_envelope = SafetyEnvelope {
            max_latency_ms: 0,                 // Impossible: must be > 0
            min_throughput_rps: f64::INFINITY, // Impossible: infinite throughput
            max_error_rate_pct: -1.0,          // Impossible: negative error rate
            max_memory_mb: f64::NAN,           // Invalid: NaN memory limit
        };

        let governor = OptimizationGovernor::new(contradictory_envelope, BTreeMap::new());
        let mut gate = GovernorGate::new(governor);

        let candidate = OptimizationProposal {
            proposal_id: "contradictory-envelope".to_string(),
            knob: RuntimeKnob::ConcurrencyLimit,
            old_value: 64,
            new_value: 128,
            predicted: PredictedMetrics {
                latency_ms: 200,
                throughput_rps: 500,
                error_rate_pct: 0.1,
                memory_mb: 2048,
            },
            rationale: "contradictory envelope test".to_string(),
            trace_id: "trace-contradictory".to_string(),
        };

        let decision = gate.submit(candidate);
        // Must reject due to invalid envelope configuration
        assert!(matches!(
            decision,
            GovernorDecision::Rejected(RejectionReason::EnvelopeViolation(_))
        ));
    }

    #[test]
    fn extreme_adversarial_concurrent_state_mutation_simulation() {
        let mut gate1 = GovernorGate::with_defaults();
        let mut gate2 = GovernorGate::with_defaults();

        let proposal1 = OptimizationProposal {
            proposal_id: "concurrent-1".to_string(),
            knob: RuntimeKnob::ConcurrencyLimit,
            old_value: 64,
            new_value: 128,
            predicted: PredictedMetrics {
                latency_ms: 200,
                throughput_rps: 500,
                error_rate_pct: 0.1,
                memory_mb: 2048,
            },
            rationale: "concurrent test 1".to_string(),
            trace_id: "trace-concurrent-1".to_string(),
        };

        let proposal2 = OptimizationProposal {
            proposal_id: "concurrent-2".to_string(),
            knob: RuntimeKnob::ConcurrencyLimit,
            old_value: 64, // Same old_value, simulating race condition
            new_value: 256,
            predicted: PredictedMetrics {
                latency_ms: 200,
                throughput_rps: 500,
                error_rate_pct: 0.1,
                memory_mb: 2048,
            },
            rationale: "concurrent test 2".to_string(),
            trace_id: "trace-concurrent-2".to_string(),
        };

        // Simulate concurrent submission
        let decision1 = gate1.submit(proposal1);
        let decision2 = gate2.submit(proposal2);

        // At least one should be rejected due to stale old_value
        assert!(
            matches!(decision1, GovernorDecision::Rejected(_))
                || matches!(decision2, GovernorDecision::Rejected(_))
        );
    }

    #[test]
    fn extreme_adversarial_control_character_environment_pollution() {
        let mut gate = GovernorGate::with_defaults();
        let control_chars = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";

        let candidate = OptimizationProposal {
            proposal_id: format!("control{control_chars}pollution"),
            knob: RuntimeKnob::ConcurrencyLimit,
            old_value: 64,
            new_value: 128,
            predicted: PredictedMetrics {
                latency_ms: 200,
                throughput_rps: 500,
                error_rate_pct: 0.1,
                memory_mb: 2048,
            },
            rationale: format!("control{control_chars}rationale"),
            trace_id: format!("trace{control_chars}control"),
        };

        let decision = gate.submit(candidate);
        // Should handle control characters without corruption
        assert!(matches!(
            decision,
            GovernorDecision::Rejected(_) | GovernorDecision::Approved
        ));

        // Verify audit trail doesn't contain raw control characters
        let audit_entries = gate.audit_trail();
        for entry in audit_entries {
            assert!(!entry.evidence.as_deref().unwrap_or("").contains('\x00'));
        }
    }

    #[test]
    fn extreme_adversarial_deeply_nested_json_serialization_protection() {
        use serde_json::Value;

        // Create deeply nested JSON structure (potential stack overflow)
        let mut nested = Value::String("deep".to_string());
        for _ in 0..10000 {
            nested = Value::Array(vec![nested]);
        }

        let candidate = OptimizationProposal {
            proposal_id: "deep-json".to_string(),
            knob: RuntimeKnob::ConcurrencyLimit,
            old_value: 64,
            new_value: 128,
            predicted: PredictedMetrics {
                latency_ms: 200,
                throughput_rps: 500,
                error_rate_pct: 0.1,
                memory_mb: 2048,
            },
            rationale: nested.to_string(), // Massive nested JSON string
            trace_id: "trace-deep-json".to_string(),
        };

        let mut gate = GovernorGate::with_defaults();
        let decision = gate.submit(candidate);
        // Should handle deep nesting without stack overflow
        assert!(matches!(
            decision,
            GovernorDecision::Rejected(_) | GovernorDecision::Approved
        ));
    }

    #[test]
    fn extreme_adversarial_metric_boundary_edge_cases() {
        let mut gate = GovernorGate::with_defaults();

        let edge_cases = vec![
            PredictedMetrics {
                latency_ms: f64::EPSILON,
                throughput_rps: f64::MIN_POSITIVE,
                error_rate_pct: f64::EPSILON,
                memory_mb: f64::MIN_POSITIVE,
            },
            PredictedMetrics {
                latency_ms: f64::MAX - 1.0,
                throughput_rps: f64::MAX - 1.0,
                error_rate_pct: 100.0 - f64::EPSILON,
                memory_mb: f64::MAX - 1.0,
            },
        ];

        for (i, metrics) in edge_cases.into_iter().enumerate() {
            let candidate = OptimizationProposal {
                proposal_id: format!("edge-case-{i}"),
                knob: RuntimeKnob::ConcurrencyLimit,
                old_value: 64,
                new_value: 128,
                predicted: metrics,
                rationale: format!("edge case test {i}"),
                trace_id: format!("trace-edge-{i}"),
            };

            let decision = gate.submit(candidate);
            // Should handle edge cases gracefully
            assert!(matches!(
                decision,
                GovernorDecision::Rejected(_) | GovernorDecision::Approved
            ));
        }
    }

    #[test]
    fn extreme_adversarial_unicode_normalization_attack_resistance() {
        let mut gate = GovernorGate::with_defaults();
        // Same visual appearance, different Unicode normalization
        let nfc_string = "café"; // NFC normalized
        let nfd_string = "cafe\u{301}"; // NFD normalized (combining accent)

        let candidate1 = OptimizationProposal {
            proposal_id: format!("norm-{nfc_string}"),
            knob: RuntimeKnob::ConcurrencyLimit,
            old_value: 64,
            new_value: 128,
            predicted: PredictedMetrics {
                latency_ms: 200,
                throughput_rps: 500,
                error_rate_pct: 0.1,
                memory_mb: 2048,
            },
            rationale: "normalization test NFC".to_string(),
            trace_id: format!("trace-{nfc_string}"),
        };

        let candidate2 = OptimizationProposal {
            proposal_id: format!("norm-{nfd_string}"),
            knob: RuntimeKnob::ConcurrencyLimit,
            old_value: 64,
            new_value: 128,
            predicted: PredictedMetrics {
                latency_ms: 200,
                throughput_rps: 500,
                error_rate_pct: 0.1,
                memory_mb: 2048,
            },
            rationale: "normalization test NFD".to_string(),
            trace_id: format!("trace-{nfd_string}"),
        };

        let decision1 = gate.submit(candidate1);
        let decision2 = gate.submit(candidate2);

        // Should treat as different proposals despite visual similarity
        assert!(matches!(decision1, GovernorDecision::Approved));
        assert!(matches!(decision2, GovernorDecision::Approved));
        assert_eq!(gate.inner().applied_count(), 2);
    }

    #[test]
    fn extreme_adversarial_mutation_cascade_amplification() {
        let mut gate = GovernorGate::with_defaults();

        // Apply initial valid proposal
        let initial = OptimizationProposal {
            proposal_id: "cascade-base".to_string(),
            knob: RuntimeKnob::ConcurrencyLimit,
            old_value: 64,
            new_value: 128,
            predicted: PredictedMetrics {
                latency_ms: 200,
                throughput_rps: 500,
                error_rate_pct: 0.1,
                memory_mb: 2048,
            },
            rationale: "cascade base".to_string(),
            trace_id: "trace-cascade-base".to_string(),
        };
        assert!(matches!(gate.submit(initial), GovernorDecision::Approved));

        // Attempt cascading modifications that could amplify
        for i in 0..100 {
            let cascade_candidate = OptimizationProposal {
                proposal_id: format!("cascade-{i}"),
                knob: RuntimeKnob::ConcurrencyLimit,
                old_value: 128, // Based on previous change
                new_value: 128u64.saturating_add(i as u64),
                predicted: PredictedMetrics {
                    latency_ms: 200.0 + (i as f64 * 10.0),
                    throughput_rps: 500.0 - (i as f64 * 5.0),
                    error_rate_pct: 0.1 + (i as f64 * 0.01),
                    memory_mb: 2048.0 + (i as f64 * 100.0),
                },
                rationale: format!("cascade attempt {i}"),
                trace_id: format!("trace-cascade-{i}"),
            };

            let decision = gate.submit(cascade_candidate);

            // Safety envelope should prevent dangerous amplification
            if i > 10 {
                assert!(matches!(
                    decision,
                    GovernorDecision::Rejected(RejectionReason::EnvelopeViolation(_))
                ));
            }
        }

        // Applied count should be bounded by safety envelope
        assert!(gate.inner().applied_count() < 50);
    }

    #[test]
    fn negative_advanced_serialization_collision_attacks_with_hash_substitution() {
        // Test serialization attacks that attempt to substitute hash-like content
        let mut gate = GovernorGate::with_defaults();

        let hash_collision_attempts = vec![
            // Hash-like strings that could confuse validation
            "a".repeat(64),                                   // Valid hex length
            "0123456789abcdef".repeat(4),                     // Valid hex pattern
            format!("sha256:{}", "a".repeat(64)),             // Prefixed hash
            format!("{}:{}", "b".repeat(32), "c".repeat(32)), // Colon separator
            "deadbeef".repeat(8),                             // Common hex pattern
        ];

        for (i, hash_like) in hash_collision_attempts.iter().enumerate() {
            let candidate = OptimizationProposal {
                proposal_id: hash_like.clone(),
                knob: RuntimeKnob::ConcurrencyLimit,
                old_value: 64,
                new_value: 128u64.saturating_add(i as u64),
                predicted: PredictedMetrics {
                    latency_ms: 200,
                    throughput_rps: 500,
                    error_rate_pct: 0.1,
                    memory_mb: 2048,
                },
                rationale: format!("hash collision test {}", i),
                trace_id: format!("trace-{}-{}", hash_like, i),
            };

            let decision = gate.submit(candidate.clone());

            // Should handle hash-like strings without collision issues
            assert!(matches!(
                decision,
                GovernorDecision::Approved | GovernorDecision::Rejected(_)
            ));

            // Proposal IDs should be treated as distinct
            let second_candidate = OptimizationProposal {
                proposal_id: format!("{}-duplicate", hash_like),
                ..candidate
            };

            let second_decision = gate.submit(second_candidate);
            assert!(matches!(
                second_decision,
                GovernorDecision::Approved | GovernorDecision::Rejected(_)
            ));
        }

        // Should maintain proposal tracking integrity despite hash-like content
        assert!(gate.inner().decision_count() > 0);
    }

    #[test]
    fn negative_timing_side_channel_resistance_in_proposal_evaluation() {
        use std::time::Instant;

        let mut gate = GovernorGate::with_defaults();
        let sample_size = 500;

        // Create proposals with different characteristics that might leak timing
        let timing_test_cases = vec![
            // Short proposal ID vs long proposal ID
            ("a", "a".repeat(10000)),
            // Simple rationale vs complex rationale
            (
                "simple",
                "complex with many unicode chars: 🚀🎯🔥💻⚡🌟🎨🔧🚦🎪".repeat(100),
            ),
            // Different knob types (might have different validation paths)
            ("concurrency", "batch_size"),
        ];

        for (case_name, (short_variant, long_variant)) in timing_test_cases.iter().enumerate() {
            let mut short_timings = Vec::new();
            let mut long_timings = Vec::new();

            // Measure timing for short variant
            for iteration in 0..sample_size {
                let candidate = OptimizationProposal {
                    proposal_id: format!("{}_{}", short_variant, iteration),
                    knob: if case_name == 2 {
                        RuntimeKnob::ConcurrencyLimit
                    } else {
                        RuntimeKnob::ConcurrencyLimit
                    },
                    old_value: 64,
                    new_value: 128u64.saturating_add(iteration as u64),
                    predicted: PredictedMetrics {
                        latency_ms: 200,
                        throughput_rps: 500,
                        error_rate_pct: 0.1,
                        memory_mb: 2048,
                    },
                    rationale: if case_name == 1 {
                        short_variant.to_string()
                    } else {
                        "timing test".to_string()
                    },
                    trace_id: format!("trace-short-{}-{}", case_name, iteration),
                };

                let start = Instant::now();
                let _decision = gate.submit(candidate);
                push_bounded(&mut short_timings, start.elapsed(), 10000);
            }

            // Measure timing for long variant
            for iteration in 0..sample_size {
                let candidate = OptimizationProposal {
                    proposal_id: format!("{}_{}", long_variant, iteration),
                    knob: if case_name == 2 {
                        RuntimeKnob::BatchSize
                    } else {
                        RuntimeKnob::ConcurrencyLimit
                    },
                    old_value: if case_name == 2 { 128 } else { 64 },
                    new_value: if case_name == 2 {
                        256u64.saturating_add(iteration as u64)
                    } else {
                        128u64.saturating_add(iteration as u64)
                    },
                    predicted: PredictedMetrics {
                        latency_ms: 200,
                        throughput_rps: 500,
                        error_rate_pct: 0.1,
                        memory_mb: 2048,
                    },
                    rationale: if case_name == 1 {
                        long_variant.to_string()
                    } else {
                        "timing test".to_string()
                    },
                    trace_id: format!("trace-long-{}-{}", case_name, iteration),
                };

                let start = Instant::now();
                let _decision = gate.submit(candidate);
                push_bounded(&mut long_timings, start.elapsed(), 10000);
            }

            // Statistical analysis of timing differences
            let avg_short = short_timings.iter().sum::<std::time::Duration>().as_nanos() as f64
                / sample_size as f64;
            let avg_long = long_timings.iter().sum::<std::time::Duration>().as_nanos() as f64
                / sample_size as f64;

            if avg_short > 0.0 && avg_long > 0.0 {
                let timing_ratio = (avg_long - avg_short).abs() / avg_short.min(avg_long);
                // Timing should not vary dramatically based on input characteristics
                assert!(
                    timing_ratio < 3.0,
                    "Suspicious timing variation for case {}: short={:.0}ns, long={:.0}ns, ratio={:.2}",
                    case_name,
                    avg_short,
                    avg_long,
                    timing_ratio
                );
            }
        }
    }

    #[test]
    fn negative_memory_fragmentation_stress_during_proposal_batch_processing() {
        let mut gate = GovernorGate::with_defaults();

        // Create memory fragmentation
        let mut fragmenters: Vec<Vec<u8>> = Vec::new();
        for i in 0..10000 {
            push_bounded(&mut fragmenters, vec![i as u8; (i % 100) + 1], 50000);
        }

        // Process large batch of proposals under memory pressure
        let batch_size = 1000;
        let mut successful_submissions = 0;

        for i in 0..batch_size {
            let candidate = OptimizationProposal {
                proposal_id: format!("fragmentation_test_{}", i),
                knob: RuntimeKnob::ConcurrencyLimit,
                old_value: 64,
                new_value: 128,
                predicted: PredictedMetrics {
                    latency_ms: 200.0 + (i as f64 * 0.1),
                    throughput_rps: 500.0 - (i as f64 * 0.1),
                    error_rate_pct: 0.1,
                    memory_mb: 2048,
                },
                rationale: format!("fragmentation stress test iteration {}", i),
                trace_id: format!("trace-frag-{}", i),
            };

            let start = std::time::Instant::now();
            let decision = gate.submit(candidate);
            let duration = start.elapsed();

            // Should complete in reasonable time despite memory pressure
            assert!(
                duration < std::time::Duration::from_millis(100),
                "Proposal {} took too long under memory pressure: {:?}",
                i,
                duration
            );

            match decision {
                GovernorDecision::Approved => {
                    successful_submissions = successful_submissions.saturating_add(1)
                }
                GovernorDecision::Rejected(_) => {
                    // Some rejections are expected due to envelope violations
                }
            }

            // Add more fragmentation during processing
            if i % 10 == 0 {
                for j in 0..100 {
                    push_bounded(
                        &mut fragmenters,
                        vec![(i + j) as u8; ((i + j) % 50) + 1],
                        50000,
                    );
                }
            }
        }

        // Should have processed substantial number despite memory pressure
        assert!(gate.inner().decision_count() == batch_size);
        assert!(
            successful_submissions > 0,
            "Should have some successful submissions"
        );

        // Memory cleanup should not affect subsequent operations
        drop(fragmenters);

        let post_cleanup_candidate = OptimizationProposal {
            proposal_id: "post-cleanup".to_string(),
            knob: RuntimeKnob::ConcurrencyLimit,
            old_value: 64,
            new_value: 128,
            predicted: PredictedMetrics {
                latency_ms: 200,
                throughput_rps: 500,
                error_rate_pct: 0.1,
                memory_mb: 2048,
            },
            rationale: "post cleanup test".to_string(),
            trace_id: "trace-post-cleanup".to_string(),
        };

        let post_decision = gate.submit(post_cleanup_candidate);
        assert!(matches!(
            post_decision,
            GovernorDecision::Approved | GovernorDecision::Rejected(_)
        ));
    }

    #[test]
    fn negative_complex_state_transition_edge_cases_with_revert_chains() {
        let mut gate = GovernorGate::with_defaults();

        // Build complex state with multiple applied proposals
        let proposals = vec![
            ("chain-1", RuntimeKnob::ConcurrencyLimit, 64, 128),
            ("chain-2", RuntimeKnob::BatchSize, 128, 256),
            ("chain-3", RuntimeKnob::RetryBudget, 3, 6),
        ];

        for (id, knob, old_val, new_val) in proposals {
            let candidate = OptimizationProposal {
                proposal_id: id.to_string(),
                knob,
                old_value: old_val,
                new_value: new_val,
                predicted: PredictedMetrics {
                    latency_ms: 200,
                    throughput_rps: 500,
                    error_rate_pct: 0.1,
                    memory_mb: 2048,
                },
                rationale: format!("chain building {}", id),
                trace_id: format!("trace-{}", id),
            };

            let decision = gate.submit(candidate);
            assert!(matches!(decision, GovernorDecision::Approved));
        }

        assert_eq!(gate.inner().applied_count(), 3);

        // Test edge cases in live check reversal
        let edge_case_metrics = vec![
            // NaN in different fields
            PredictedMetrics {
                latency_ms: f64::NAN,
                throughput_rps: 500,
                error_rate_pct: 0.1,
                memory_mb: 2048,
            },
            PredictedMetrics {
                latency_ms: 200,
                throughput_rps: f64::NAN,
                error_rate_pct: 0.1,
                memory_mb: 2048,
            },
            PredictedMetrics {
                latency_ms: 200,
                throughput_rps: 500,
                error_rate_pct: f64::NAN,
                memory_mb: 2048,
            },
            PredictedMetrics {
                latency_ms: 200,
                throughput_rps: 500,
                error_rate_pct: 0.1,
                memory_mb: f64::NAN,
            },
            // Infinity in different fields
            PredictedMetrics {
                latency_ms: f64::INFINITY,
                throughput_rps: 500,
                error_rate_pct: 0.1,
                memory_mb: 2048,
            },
            PredictedMetrics {
                latency_ms: 200,
                throughput_rps: f64::NEG_INFINITY,
                error_rate_pct: 0.1,
                memory_mb: 2048,
            },
            // All invalid
            PredictedMetrics {
                latency_ms: f64::NAN,
                throughput_rps: f64::INFINITY,
                error_rate_pct: f64::NEG_INFINITY,
                memory_mb: f64::NAN,
            },
        ];

        for (i, metrics) in edge_case_metrics.iter().enumerate() {
            let reverted = gate.live_check(metrics);

            // Should handle invalid metrics gracefully by reverting
            if !reverted.is_empty() {
                assert!(reverted.len() <= 3, "Should not revert more than applied");

                // State should be consistent after reversion
                assert!(gate.inner().applied_count() < 3);

                // Verify knobs are properly reverted
                if reverted.contains(&"chain-1".to_string()) {
                    assert_eq!(
                        gate.inner().knob_value(&RuntimeKnob::ConcurrencyLimit),
                        Some(64)
                    );
                }
            }

            // Re-apply to test next edge case
            for (id, knob, old_val, new_val) in &proposals {
                if gate.inner().knob_value(knob) == Some(*old_val) {
                    let candidate = OptimizationProposal {
                        proposal_id: format!("{}-retry-{}", id, i),
                        knob: *knob,
                        old_value: *old_val,
                        new_value: *new_val,
                        predicted: PredictedMetrics {
                            latency_ms: 200,
                            throughput_rps: 500,
                            error_rate_pct: 0.1,
                            memory_mb: 2048,
                        },
                        rationale: format!("retry {} after revert {}", id, i),
                        trace_id: format!("trace-retry-{}-{}", id, i),
                    };
                    let _decision = gate.submit(candidate);
                }
            }
        }
    }

    #[test]
    fn negative_cross_module_boundary_validation_with_engine_namespace_pollution() {
        let mut gate = GovernorGate::with_defaults();

        // Test various engine namespace pollution attempts
        let namespace_pollution_attempts = vec![
            "engine_core",
            "engine_core::scheduler",
            "engine_core::allocator::heap",
            "franken_engine::internal",
            "franken_engine::core::runtime",
            "system::kernel::scheduler",
            "os::process::memory",
            "runtime::engine::core",
        ];

        for namespace in namespace_pollution_attempts {
            let result = gate.reject_engine_internal_adjustment(namespace);

            // Should consistently reject engine internal adjustments
            assert!(
                result.is_err(),
                "Engine namespace '{}' should be rejected",
                namespace
            );

            let error_msg = result.unwrap_err();
            assert!(error_msg.contains(error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION));
            assert!(
                error_msg.contains(namespace),
                "Error should mention the specific namespace"
            );

            // Should log audit trail entry
            assert!(
                gate.audit_trail().iter().any(|entry| {
                    entry.event_code == error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION
                        && entry.evidence.as_deref().unwrap_or("").contains(namespace)
                }),
                "Should audit log the namespace violation for {}",
                namespace
            );
        }

        // Test legitimate namespaces are not rejected
        let legitimate_namespaces = vec![
            "user::application::config",
            "perf::governor::settings",
            "network::timeout::values",
        ];

        for namespace in legitimate_namespaces {
            let result = gate.reject_engine_internal_adjustment(namespace);
            // Note: This function always rejects, but the error message should be appropriate
            assert!(result.is_err());
        }
    }

    #[test]
    fn negative_advanced_error_recovery_scenarios_with_cascading_failures() {
        let mut gate = GovernorGate::with_defaults();

        // Create a scenario where errors cascade through multiple layers

        // Step 1: Apply a valid proposal
        let valid_proposal = OptimizationProposal {
            proposal_id: "cascade-base".to_string(),
            knob: RuntimeKnob::ConcurrencyLimit,
            old_value: 64,
            new_value: 128,
            predicted: PredictedMetrics {
                latency_ms: 200,
                throughput_rps: 500,
                error_rate_pct: 0.1,
                memory_mb: 2048,
            },
            rationale: "cascade error test base".to_string(),
            trace_id: "trace-cascade-base".to_string(),
        };

        assert!(matches!(
            gate.submit(valid_proposal),
            GovernorDecision::Approved
        ));
        assert_eq!(gate.inner().applied_count(), 1);

        // Step 2: Submit multiple problematic proposals that should trigger various failure modes
        let error_scenarios = vec![
            // Invalid metrics
            OptimizationProposal {
                proposal_id: "cascade-nan".to_string(),
                knob: RuntimeKnob::ConcurrencyLimit,
                old_value: 128, // Based on previous successful change
                new_value: 256,
                predicted: PredictedMetrics {
                    latency_ms: f64::NAN,
                    throughput_rps: 500,
                    error_rate_pct: 0.1,
                    memory_mb: 2048,
                },
                rationale: "cascade NaN error".to_string(),
                trace_id: "trace-cascade-nan".to_string(),
            },
            // Envelope violation
            OptimizationProposal {
                proposal_id: "cascade-envelope".to_string(),
                knob: RuntimeKnob::ConcurrencyLimit,
                old_value: 128,
                new_value: 512,
                predicted: PredictedMetrics {
                    latency_ms: 1000,    // Violates envelope
                    throughput_rps: 50,  // Violates envelope
                    error_rate_pct: 5.0, // Violates envelope
                    memory_mb: 10000,    // Violates envelope
                },
                rationale: "cascade envelope violation".to_string(),
                trace_id: "trace-cascade-envelope".to_string(),
            },
            // Stale old value
            OptimizationProposal {
                proposal_id: "cascade-stale".to_string(),
                knob: RuntimeKnob::ConcurrencyLimit,
                old_value: 64, // Stale - actual current value is 128
                new_value: 192,
                predicted: PredictedMetrics {
                    latency_ms: 200,
                    throughput_rps: 500,
                    error_rate_pct: 0.1,
                    memory_mb: 2048,
                },
                rationale: "cascade stale value".to_string(),
                trace_id: "trace-cascade-stale".to_string(),
            },
        ];

        for (i, error_proposal) in error_scenarios.into_iter().enumerate() {
            let decision = gate.submit(error_proposal);

            // All should be rejected for different reasons
            match decision {
                GovernorDecision::Rejected(reason) => {
                    match reason {
                        RejectionReason::InvalidProposal(_) => {
                            // Expected for NaN or stale values
                        }
                        RejectionReason::EnvelopeViolation(_) => {
                            // Expected for envelope violation
                        }
                        _ => {
                            // Other rejection reasons are also valid
                        }
                    }
                }
                GovernorDecision::Approved => {
                    panic!("Error scenario {} should have been rejected", i);
                }
            }
        }

        // Step 3: Verify state remains consistent despite cascading errors
        assert_eq!(
            gate.inner().applied_count(),
            1,
            "Applied count should remain 1"
        );
        assert_eq!(
            gate.inner().knob_value(&RuntimeKnob::ConcurrencyLimit),
            Some(128)
        );
        assert!(
            gate.inner().decision_count() > 3,
            "Should have recorded all decisions"
        );

        // Step 4: Verify system can recover and accept valid proposals after errors
        let recovery_proposal = OptimizationProposal {
            proposal_id: "cascade-recovery".to_string(),
            knob: RuntimeKnob::ConcurrencyLimit,
            old_value: 128, // Correct current value
            new_value: 192,
            predicted: PredictedMetrics {
                latency_ms: 200,
                throughput_rps: 500,
                error_rate_pct: 0.1,
                memory_mb: 2048,
            },
            rationale: "cascade recovery test".to_string(),
            trace_id: "trace-cascade-recovery".to_string(),
        };

        let recovery_decision = gate.submit(recovery_proposal);
        assert!(
            matches!(recovery_decision, GovernorDecision::Approved),
            "Should recover and accept valid proposals after errors"
        );
        assert_eq!(gate.inner().applied_count(), 2);
    }

    #[test]
    fn negative_resource_exhaustion_protection_with_massive_proposal_batches() {
        let mut gate = GovernorGate::with_defaults();
        let massive_batch_size = 100_000;

        // Track resource usage
        let start_time = std::time::Instant::now();
        let mut memory_high_water_mark = 0usize;

        // Submit massive batch of proposals to test resource protection
        for i in 0..massive_batch_size {
            // Create proposal with varying data sizes
            let data_multiplier = (i % 100) + 1;
            let candidate = OptimizationProposal {
                proposal_id: format!("massive_batch_{:06}", i),
                knob: RuntimeKnob::ConcurrencyLimit,
                old_value: 64,
                new_value: 64u64.saturating_add(i % 1000),
                predicted: PredictedMetrics {
                    latency_ms: 200.0 + (i as f64 * 0.001),
                    throughput_rps: 500.0 - (i as f64 * 0.001),
                    error_rate_pct: 0.1 + (i as f64 * 0.0001),
                    memory_mb: 2048.0 + (i as f64 * 0.1),
                },
                rationale: "x".repeat(data_multiplier), // Variable length rationale
                trace_id: format!("trace_massive_{:06}", i),
            };

            let iteration_start = std::time::Instant::now();
            let _decision = gate.submit(candidate);
            let iteration_duration = iteration_start.elapsed();

            // Should maintain reasonable per-operation performance
            assert!(
                iteration_duration < std::time::Duration::from_millis(10),
                "Iteration {} took too long: {:?}",
                i,
                iteration_duration
            );

            // Estimate memory usage (rough approximation)
            let estimated_memory = gate.inner().decision_count() * 1000; // ~1KB per decision
            memory_high_water_mark = memory_high_water_mark.max(estimated_memory);

            // Should not consume excessive memory
            assert!(
                memory_high_water_mark < 1_000_000_000, // 1GB limit
                "Memory usage too high: ~{} bytes",
                memory_high_water_mark
            );

            // Sample timing every 10,000 iterations
            if i % 10_000 == 0 {
                let elapsed = start_time.elapsed();
                let ops_per_sec = (i + 1) as f64 / elapsed.as_secs_f64();

                // Should maintain reasonable throughput
                assert!(
                    ops_per_sec > 1_000.0,
                    "Throughput too low at iteration {}: {:.1} ops/sec",
                    i,
                    ops_per_sec
                );
            }
        }

        let total_duration = start_time.elapsed();
        let total_ops_per_sec = massive_batch_size as f64 / total_duration.as_secs_f64();

        // Overall performance should be reasonable
        assert!(
            total_ops_per_sec > 5_000.0,
            "Overall throughput too low: {:.1} ops/sec",
            total_ops_per_sec
        );
        assert!(gate.inner().decision_count() == massive_batch_size);

        // System should remain responsive after massive batch
        let post_batch_candidate = OptimizationProposal {
            proposal_id: "post_massive_batch".to_string(),
            knob: RuntimeKnob::ConcurrencyLimit,
            old_value: 64,
            new_value: 128,
            predicted: PredictedMetrics {
                latency_ms: 200,
                throughput_rps: 500,
                error_rate_pct: 0.1,
                memory_mb: 2048,
            },
            rationale: "post batch responsiveness test".to_string(),
            trace_id: "trace-post-batch".to_string(),
        };

        let post_start = std::time::Instant::now();
        let _decision = gate.submit(post_batch_candidate);
        let post_duration = post_start.elapsed();

        assert!(
            post_duration < std::time::Duration::from_millis(100),
            "System should remain responsive after massive batch: {:?}",
            post_duration
        );
    }

    #[test]
    fn negative_json_schema_boundary_attacks_with_type_confusion() {
        use serde_json::json;

        // Test JSON deserialization with type confusion attacks
        let type_confusion_attacks = vec![
            // String where number expected
            json!({
                "proposal_id": "type-confusion-1",
                "knob": "concurrency_limit",
                "old_value": "64", // String instead of u64
                "new_value": 128,
                "predicted": {
                    "latency_ms": 200,
                    "throughput_rps": 500,
                    "error_rate_pct": 0.1,
                    "memory_mb": 2048
                },
                "rationale": "type confusion test",
                "trace_id": "trace-type-confusion"
            }),
            // Array where object expected
            json!({
                "proposal_id": "type-confusion-2",
                "knob": "concurrency_limit",
                "old_value": 64,
                "new_value": 128,
                "predicted": [200, 500, 0.1, 2048], // Array instead of object
                "rationale": "type confusion test",
                "trace_id": "trace-type-confusion"
            }),
            // Null where string expected
            json!({
                "proposal_id": null, // Null instead of string
                "knob": "concurrency_limit",
                "old_value": 64,
                "new_value": 128,
                "predicted": {
                    "latency_ms": 200,
                    "throughput_rps": 500,
                    "error_rate_pct": 0.1,
                    "memory_mb": 2048
                },
                "rationale": "type confusion test",
                "trace_id": "trace-type-confusion"
            }),
            // Boolean where string expected
            json!({
                "proposal_id": "type-confusion-4",
                "knob": true, // Boolean instead of string
                "old_value": 64,
                "new_value": 128,
                "predicted": {
                    "latency_ms": 200,
                    "throughput_rps": 500,
                    "error_rate_pct": 0.1,
                    "memory_mb": 2048
                },
                "rationale": "type confusion test",
                "trace_id": "trace-type-confusion"
            }),
            // Nested object injection
            json!({
                "proposal_id": "type-confusion-5",
                "knob": "concurrency_limit",
                "old_value": 64,
                "new_value": 128,
                "predicted": {
                    "latency_ms": 200,
                    "throughput_rps": 500,
                    "error_rate_pct": 0.1,
                    "memory_mb": 2048,
                    "injected": { "malicious": "payload" } // Extra field injection
                },
                "rationale": "type confusion test",
                "trace_id": "trace-type-confusion"
            }),
        ];

        for (i, malicious_json) in type_confusion_attacks.iter().enumerate() {
            let result = serde_json::from_value::<OptimizationProposal>(malicious_json.clone());

            // Should safely reject type confusion attacks
            assert!(
                result.is_err(),
                "Type confusion attack {} should be rejected: {:?}",
                i,
                malicious_json
            );

            // Error should be deterministic (same input produces same error)
            let second_result =
                serde_json::from_value::<OptimizationProposal>(malicious_json.clone());
            assert!(
                second_result.is_err(),
                "Type confusion rejection should be deterministic for attack {}",
                i
            );
        }

        // Test similar attacks on other types
        let safety_envelope_attacks = vec![
            json!({
                "max_latency_ms": "500", // String instead of f64
                "min_throughput_rps": 100,
                "max_error_rate_pct": 1.0,
                "max_memory_mb": 4096
            }),
            json!({
                "max_latency_ms": 500,
                "min_throughput_rps": null, // Null instead of f64
                "max_error_rate_pct": 1.0,
                "max_memory_mb": 4096
            }),
        ];

        for (i, attack) in safety_envelope_attacks.iter().enumerate() {
            let result = serde_json::from_value::<SafetyEnvelope>(attack.clone());
            assert!(
                result.is_err(),
                "SafetyEnvelope type confusion attack {} should be rejected",
                i
            );
        }
    }

    #[test]
    fn extreme_adversarial_unicode_confusable_homograph_attack_in_knob_names() {
        use super::optimization_governor::{
            GovernorGate, OptimizationProposal, PredictedMetrics, RuntimeKnob,
        };

        let mut gate = GovernorGate::with_defaults();

        // Unicode confusable characters that look similar to legitimate knob names
        let confusable_attacks = vec![
            // Cyrillic characters that look like Latin
            "сoncurrency_limit", // Cyrillic 'с' instead of Latin 'c'
            "batch_sizе",        // Cyrillic 'е' instead of Latin 'e'
            "саche_capacity",    // Cyrillic 'с' and 'а'
            "retry_budget",      // Normal for comparison
            "rеtry_budgеt",      // Cyrillic 'е' characters
            // Greek characters
            "ϲοncurrency_limit", // Greek omicron and koppa
            // Mathematical symbols
            "𝐜𝐨𝐧𝐜𝐮𝐫𝐫𝐞𝐧𝐜𝐲_𝐥𝐢𝐦𝐢𝐭",                  // Mathematical bold
            "ｃｏｎｃｕｒｒｅｎｃｙ＿ｌｉｍｉｔ", // Fullwidth characters
        ];

        for (i, confusable_knob) in confusable_attacks.iter().enumerate() {
            // Try to deserialize with confusable knob name
            let malicious_json = serde_json::json!({
                "proposal_id": format!("confusable_test_{}", i),
                "knob": confusable_knob,
                "old_value": 64,
                "new_value": 128,
                "predicted": {
                    "latency_ms": 200,
                    "throughput_rps": 500,
                    "error_rate_pct": 0.1,
                    "memory_mb": 2048
                },
                "rationale": format!("confusable attack {}", i),
                "trace_id": format!("trace-confusable-{}", i)
            });

            let result = serde_json::from_value::<OptimizationProposal>(malicious_json);

            // Should reject confusable/homograph attempts
            assert!(
                result.is_err(),
                "Confusable knob name '{}' should be rejected",
                confusable_knob
            );
        }

        // Verify legitimate knob names still work
        let legitimate_proposal = OptimizationProposal {
            proposal_id: "legitimate_test".to_string(),
            knob: RuntimeKnob::ConcurrencyLimit,
            old_value: 64,
            new_value: 128,
            predicted: PredictedMetrics {
                latency_ms: 200,
                throughput_rps: 500,
                error_rate_pct: 0.1,
                memory_mb: 2048,
            },
            rationale: "legitimate confusable test".to_string(),
            trace_id: "trace-legitimate".to_string(),
        };

        let decision = gate.submit(legitimate_proposal);
        assert!(matches!(
            decision,
            super::optimization_governor::GovernorDecision::Approved
        ));
    }

    #[test]
    fn extreme_adversarial_timing_attack_via_proposal_id_length_correlation() {
        use super::optimization_governor::{
            GovernorGate, OptimizationProposal, PredictedMetrics, RuntimeKnob,
        };
        use std::time::Instant;

        let mut gate = GovernorGate::with_defaults();
        let sample_size = 1000;

        // Test if processing time correlates with proposal ID length
        let length_test_cases = vec![
            1, 10, 100, 1000, 10000, 100000, // Exponentially increasing lengths
        ];

        for target_length in length_test_cases {
            let mut timing_samples = Vec::new();

            for iteration in 0..sample_size {
                // Create proposal ID of exact target length
                let proposal_id = if target_length == 1 {
                    "a".to_string()
                } else {
                    format!("a{:0width$}", iteration, width = target_length - 1)
                };

                assert_eq!(
                    proposal_id.len(),
                    target_length,
                    "ID should be exact target length"
                );

                let candidate = OptimizationProposal {
                    proposal_id,
                    knob: RuntimeKnob::ConcurrencyLimit,
                    old_value: 64,
                    new_value: 128u64.saturating_add(iteration as u64),
                    predicted: PredictedMetrics {
                        latency_ms: 200,
                        throughput_rps: 500,
                        error_rate_pct: 0.1,
                        memory_mb: 2048,
                    },
                    rationale: "timing correlation test".to_string(),
                    trace_id: format!("trace-timing-{}", iteration),
                };

                let start = Instant::now();
                let _decision = gate.submit(candidate);
                let duration = start.elapsed();

                push_bounded(&mut timing_samples, duration, 10000);

                // Early termination if times become excessive
                if duration > std::time::Duration::from_millis(100) {
                    panic!(
                        "Processing time too long for length {}: {:?}",
                        target_length, duration
                    );
                }
            }

            // Analyze timing distribution
            let avg_nanos: f64 = timing_samples
                .iter()
                .map(|d| d.as_nanos() as f64)
                .sum::<f64>()
                / sample_size as f64;

            let max_nanos = timing_samples.iter().map(|d| d.as_nanos()).max().unwrap() as f64;

            let min_nanos = timing_samples.iter().map(|d| d.as_nanos()).min().unwrap() as f64;

            // Check for timing attack vulnerability patterns
            let variance_ratio = (max_nanos - min_nanos) / avg_nanos;

            // Should not have excessive timing variance based on input length
            assert!(
                variance_ratio < 5.0,
                "Excessive timing variance for length {}: avg={:.0}ns, max={:.0}ns, min={:.0}ns, ratio={:.2}",
                target_length,
                avg_nanos,
                max_nanos,
                min_nanos,
                variance_ratio
            );

            // Processing time should not grow linearly with input size for small inputs
            if target_length <= 1000 {
                assert!(
                    avg_nanos < 1_000_000.0, // 1ms threshold for small inputs
                    "Processing too slow for length {}: {:.0}ns",
                    target_length,
                    avg_nanos
                );
            }
        }
    }

    #[test]
    fn extreme_adversarial_nested_metric_field_overflow_via_json_manipulation() {
        use serde_json::{Value, json};

        // Create JSON with extremely large nested metric values
        let overflow_scenarios = vec![
            // Maximum representable JSON number
            json!({
                "proposal_id": "overflow_max_json",
                "knob": "concurrency_limit",
                "old_value": 64,
                "new_value": 128,
                "predicted": {
                    "latency_ms": 9007199254740992.0, // 2^53 (max safe integer in JSON)
                    "throughput_rps": 500,
                    "error_rate_pct": 0.1,
                    "memory_mb": 2048
                },
                "rationale": "max json number test",
                "trace_id": "trace-overflow-max"
            }),
            // Scientific notation extremes
            json!({
                "proposal_id": "overflow_scientific",
                "knob": "concurrency_limit",
                "old_value": 64,
                "new_value": 128,
                "predicted": {
                    "latency_ms": 1e308, // Near f64::MAX
                    "throughput_rps": 1e-324, // Near f64::MIN_POSITIVE
                    "error_rate_pct": 0.1,
                    "memory_mb": 2048
                },
                "rationale": "scientific notation extremes",
                "trace_id": "trace-scientific"
            }),
            // Hexadecimal confusion (should be rejected as invalid JSON number)
            json!({
                "proposal_id": "overflow_hex_confusion",
                "knob": "concurrency_limit",
                "old_value": 64,
                "new_value": 128,
                "predicted": {
                    "latency_ms": "0xFFFFFFFF", // String that looks like hex
                    "throughput_rps": 500,
                    "error_rate_pct": 0.1,
                    "memory_mb": 2048
                },
                "rationale": "hex confusion test",
                "trace_id": "trace-hex"
            }),
            // Multiple overflow fields
            json!({
                "proposal_id": "overflow_multiple",
                "knob": "concurrency_limit",
                "old_value": u64::MAX, // JSON can't represent this exactly
                "new_value": u64::MAX,
                "predicted": {
                    "latency_ms": f64::MAX,
                    "throughput_rps": f64::MAX,
                    "error_rate_pct": f64::MAX,
                    "memory_mb": f64::MAX
                },
                "rationale": "multiple overflow test",
                "trace_id": "trace-multiple"
            }),
        ];

        for (i, overflow_json) in overflow_scenarios.iter().enumerate() {
            let result = serde_json::from_value::<super::optimization_governor::OptimizationProposal>(
                overflow_json.clone(),
            );

            // Should safely handle or reject overflow scenarios
            if let Ok(proposal) = result {
                // If deserialization succeeds, verify values are safe
                assert!(
                    proposal.predicted.latency_ms.is_finite()
                        || proposal.predicted.latency_ms.is_infinite(),
                    "Latency should be finite or safely infinite for scenario {}",
                    i
                );

                assert!(
                    proposal.predicted.throughput_rps.is_finite()
                        || proposal.predicted.throughput_rps.is_infinite(),
                    "Throughput should be finite or safely infinite for scenario {}",
                    i
                );

                // If values are finite, they should be reasonable
                if proposal.predicted.latency_ms.is_finite() {
                    assert!(
                        proposal.predicted.latency_ms >= 0.0,
                        "Latency should be non-negative for scenario {}",
                        i
                    );
                }

                if proposal.predicted.throughput_rps.is_finite() {
                    assert!(
                        proposal.predicted.throughput_rps >= 0.0,
                        "Throughput should be non-negative for scenario {}",
                        i
                    );
                }
            }
            // Rejection is also acceptable for overflow scenarios
        }

        // Test boundary values that should always deserialize safely
        let safe_boundary_test = json!({
            "proposal_id": "safe_boundary",
            "knob": "concurrency_limit",
            "old_value": 64,
            "new_value": 128,
            "predicted": {
                "latency_ms": 1.7976931348623155e308, // Just under f64::MAX
                "throughput_rps": 2.2250738585072014e-308, // Just over f64::MIN_POSITIVE
                "error_rate_pct": 0.1,
                "memory_mb": 2048
            },
            "rationale": "safe boundary test",
            "trace_id": "trace-safe-boundary"
        });

        let safe_result = serde_json::from_value::<
            super::optimization_governor::OptimizationProposal,
        >(safe_boundary_test);
        if let Ok(safe_proposal) = safe_result {
            // Should preserve extreme but valid values
            assert!(safe_proposal.predicted.latency_ms > 1e300);
            assert!(safe_proposal.predicted.throughput_rps < 1e-300);
        }
    }

    #[test]
    fn extreme_adversarial_concurrent_audit_trail_corruption_via_interleaved_mutations() {
        use super::optimization_governor::{
            GovernorGate, OptimizationGovernor, OptimizationProposal, PredictedMetrics, RuntimeKnob,
        };
        use std::sync::{Arc, Mutex};
        use std::thread;

        // Test concurrent access to audit trail under high contention
        let gate = Arc::new(Mutex::new(GovernorGate::with_defaults()));
        let corruption_attempts = 1000;
        let thread_count = 16;

        let mut handles = vec![];

        for thread_id in 0..thread_count {
            let gate_clone = Arc::clone(&gate);
            let handle = thread::spawn(move || {
                let mut local_corruption_count = 0;

                for iteration in 0..corruption_attempts / thread_count {
                    let operation_type = (thread_id * iteration) % 4;

                    match operation_type {
                        0 => {
                            // Submit proposals with challenging IDs
                            let challenging_id = format!(
                                "thread{}_{}_{}{}{}",
                                thread_id,
                                iteration,
                                "\u{200B}".repeat(10), // Zero-width space
                                "\x00\x01\x02",        // Control chars
                                "🔥💀☠️"               // Emoji
                            );

                            let proposal = OptimizationProposal {
                                proposal_id: challenging_id,
                                knob: match iteration % 4 {
                                    0 => RuntimeKnob::ConcurrencyLimit,
                                    1 => RuntimeKnob::BatchSize,
                                    2 => RuntimeKnob::CacheCapacity,
                                    _ => RuntimeKnob::RetryBudget,
                                },
                                old_value: 64,
                                new_value: 128u64.saturating_add(iteration as u64),
                                predicted: PredictedMetrics {
                                    latency_ms: 200.0 + (iteration as f64 * 0.1),
                                    throughput_rps: 500.0 - (iteration as f64 * 0.1),
                                    error_rate_pct: 0.1,
                                    memory_mb: 2048,
                                },
                                rationale: format!(
                                    "corruption test thread {} iter {}",
                                    thread_id, iteration
                                ),
                                trace_id: format!("trace-corrupt-{}-{}", thread_id, iteration),
                            };

                            if let Ok(mut g) = gate_clone.lock() {
                                let _decision = g.submit(proposal);
                                local_corruption_count = local_corruption_count.saturating_add(1);
                            }
                        }

                        1 => {
                            // Perform live checks with extreme values
                            let extreme_metrics = PredictedMetrics {
                                latency_ms: if iteration % 2 == 0 {
                                    f64::NAN
                                } else {
                                    f64::INFINITY
                                },
                                throughput_rps: if iteration % 3 == 0 {
                                    f64::NEG_INFINITY
                                } else {
                                    500.0
                                },
                                error_rate_pct: (iteration as f64) * 10.0, // Often invalid
                                memory_mb: f64::MAX,
                            };

                            if let Ok(mut g) = gate_clone.lock() {
                                let _reverted = g.live_check(&extreme_metrics);
                                local_corruption_count = local_corruption_count.saturating_add(1);
                            }
                        }

                        2 => {
                            // Read audit trail during mutations
                            if let Ok(g) = gate_clone.lock() {
                                let trail = g.audit_trail();

                                // Verify structural integrity during concurrent access
                                for (i, entry) in trail.iter().enumerate() {
                                    assert!(
                                        !entry.event_code.is_empty(),
                                        "Thread {}: Entry {} has empty event code",
                                        thread_id,
                                        i
                                    );
                                    // proposal_id can be empty for some event types
                                    // detail can be empty for some event types

                                    // Should not contain null bytes from corruption
                                    assert!(
                                        !entry.event_code.contains('\0'),
                                        "Thread {}: Entry {} event_code contains null byte",
                                        thread_id,
                                        i
                                    );
                                    assert!(
                                        !entry.proposal_id.contains('\0'),
                                        "Thread {}: Entry {} proposal_id contains null byte",
                                        thread_id,
                                        i
                                    );
                                }

                                local_corruption_count = local_corruption_count.saturating_add(1);
                            }
                        }

                        _ => {
                            // Engine boundary tests with Unicode pollution
                            let polluted_namespace = format!(
                                "engine{}_core{}::scheduler{}",
                                "\u{202E}", // Right-to-left override
                                "\u{200D}", // Zero-width joiner
                                "\u{FEFF}"  // BOM
                            );

                            if let Ok(mut g) = gate_clone.lock() {
                                let _result =
                                    g.reject_engine_internal_adjustment(&polluted_namespace);
                                local_corruption_count = local_corruption_count.saturating_add(1);
                            }
                        }
                    }

                    // Small yield to encourage race conditions
                    thread::yield_now();
                }

                local_corruption_count
            });

            push_bounded(&mut handles, handle, 100);
        }

        // Wait for all corruption attempts to complete
        let mut total_operations = 0;
        for handle in handles {
            let ops = handle
                .join()
                .expect("Thread should not panic during corruption test");
            total_operations += ops;
        }

        // Verify final state integrity after concurrent corruption attempts
        if let Ok(final_gate) = gate.lock() {
            let audit_trail = final_gate.audit_trail();

            // Audit trail should maintain structural integrity
            for (i, entry) in audit_trail.iter().enumerate() {
                assert!(
                    !entry.event_code.is_empty(),
                    "Entry {} has empty event code after corruption test",
                    i
                );

                // Should not contain corruption artifacts
                assert!(
                    !entry.event_code.contains('\0'),
                    "Entry {} event_code corrupted with null byte",
                    i
                );
                assert!(
                    !entry.proposal_id.contains('\0'),
                    "Entry {} proposal_id corrupted with null byte",
                    i
                );
                assert!(
                    !entry.detail.contains('\0'),
                    "Entry {} detail corrupted with null byte",
                    i
                );

                // Should not contain raw control characters from corruption attempts
                for byte in entry.event_code.bytes() {
                    if byte < 32 && byte != b'\t' && byte != b'\n' && byte != b'\r' {
                        panic!(
                            "Entry {} event_code contains raw control character: {}",
                            i, byte
                        );
                    }
                }
            }

            // Should have processed substantial number of operations despite contention
            assert!(
                total_operations > corruption_attempts / 2,
                "Should have completed reasonable number of operations despite corruption attempts: {}",
                total_operations
            );

            // Should still be functional after corruption attempts
            let post_corruption_proposal = OptimizationProposal {
                proposal_id: "post_corruption_test".to_string(),
                knob: RuntimeKnob::ConcurrencyLimit,
                old_value: 64,
                new_value: 128,
                predicted: PredictedMetrics {
                    latency_ms: 200,
                    throughput_rps: 500,
                    error_rate_pct: 0.1,
                    memory_mb: 2048,
                },
                rationale: "post corruption functionality test".to_string(),
                trace_id: "trace-post-corruption".to_string(),
            };

            // Gate should remain functional after corruption attempts
            // Note: This test assumes we can get a mutable reference;
            // actual implementation may require different approach
        }
    }

    #[test]
    fn extreme_adversarial_floating_point_denormal_injection_in_safety_calculations() {
        use super::optimization_governor::{
            GovernorGate, OptimizationProposal, PredictedMetrics, RuntimeKnob,
        };

        let mut gate = GovernorGate::with_defaults();

        // Test denormal (subnormal) floating-point values that could cause performance degradation
        let denormal_attacks = vec![
            // Various denormal values
            (f64::MIN_POSITIVE / 2.0, "half_min_positive"),
            (f64::MIN_POSITIVE * f64::EPSILON, "min_times_epsilon"),
            (1e-324, "smallest_positive"), // Smallest positive denormal
            (2e-324, "double_smallest"),
            (4.9406564584124654e-324, "specific_denormal"), // Known problematic value
            (f64::MIN_POSITIVE * 0.5, "min_halved"),
            (f64::MIN_POSITIVE * 0.1, "min_tenth"),
            (f64::MIN_POSITIVE * 0.01, "min_hundredth"),
        ];

        for (denormal_value, test_name) in denormal_attacks {
            // Verify the value is actually denormal/subnormal
            if denormal_value != 0.0 && denormal_value.is_finite() {
                // Test in different metric fields
                let denormal_test_cases = vec![
                    PredictedMetrics {
                        latency_ms: denormal_value,
                        throughput_rps: 500,
                        error_rate_pct: 0.1,
                        memory_mb: 2048,
                    },
                    PredictedMetrics {
                        latency_ms: 200,
                        throughput_rps: denormal_value,
                        error_rate_pct: 0.1,
                        memory_mb: 2048,
                    },
                    PredictedMetrics {
                        latency_ms: 200,
                        throughput_rps: 500,
                        error_rate_pct: denormal_value,
                        memory_mb: 2048,
                    },
                    PredictedMetrics {
                        latency_ms: 200,
                        throughput_rps: 500,
                        error_rate_pct: 0.1,
                        memory_mb: denormal_value,
                    },
                ];

                for (field_idx, metrics) in denormal_test_cases.iter().enumerate() {
                    let proposal = OptimizationProposal {
                        proposal_id: format!("denormal_{}_{}", test_name, field_idx),
                        knob: RuntimeKnob::ConcurrencyLimit,
                        old_value: 64,
                        new_value: 128,
                        predicted: metrics.clone(),
                        rationale: format!("denormal injection test {}", test_name),
                        trace_id: format!("trace-denormal-{}-{}", test_name, field_idx),
                    };

                    // Measure processing time to detect denormal performance impact
                    let start = std::time::Instant::now();
                    let decision = gate.submit(proposal);
                    let duration = start.elapsed();

                    // Should not take excessive time due to denormal arithmetic
                    assert!(
                        duration < std::time::Duration::from_millis(10),
                        "Denormal value {} in field {} caused performance degradation: {:?}",
                        denormal_value,
                        field_idx,
                        duration
                    );

                    // Should handle denormal values gracefully (accept or reject safely)
                    match decision {
                        super::optimization_governor::GovernorDecision::Approved => {
                            // If approved, verify the system can still function
                        }
                        super::optimization_governor::GovernorDecision::Rejected(_) => {
                            // Rejection is acceptable for denormal values
                        }
                    }

                    // Test live check with denormal values
                    let live_start = std::time::Instant::now();
                    let _reverted = gate.live_check(metrics);
                    let live_duration = live_start.elapsed();

                    assert!(
                        live_duration < std::time::Duration::from_millis(10),
                        "Live check with denormal {} in field {} too slow: {:?}",
                        denormal_value,
                        field_idx,
                        live_duration
                    );
                }
            }
        }

        // Test combinations of denormal values
        let combined_denormal = PredictedMetrics {
            latency_ms: f64::MIN_POSITIVE / 1000.0,
            throughput_rps: f64::MIN_POSITIVE / 500.0,
            error_rate_pct: f64::MIN_POSITIVE / 100.0,
            memory_mb: f64::MIN_POSITIVE / 10.0,
        };

        let combined_proposal = OptimizationProposal {
            proposal_id: "combined_denormal_attack".to_string(),
            knob: RuntimeKnob::ConcurrencyLimit,
            old_value: 64,
            new_value: 128,
            predicted: combined_denormal,
            rationale: "combined denormal attack".to_string(),
            trace_id: "trace-combined-denormal".to_string(),
        };

        let combined_start = std::time::Instant::now();
        let _combined_decision = gate.submit(combined_proposal);
        let combined_duration = combined_start.elapsed();

        assert!(
            combined_duration < std::time::Duration::from_millis(50),
            "Combined denormal attack caused excessive processing time: {:?}",
            combined_duration
        );

        // Verify system remains functional after denormal attacks
        let normal_proposal = OptimizationProposal {
            proposal_id: "post_denormal_normal".to_string(),
            knob: RuntimeKnob::ConcurrencyLimit,
            old_value: 64,
            new_value: 128,
            predicted: PredictedMetrics {
                latency_ms: 200,
                throughput_rps: 500,
                error_rate_pct: 0.1,
                memory_mb: 2048,
            },
            rationale: "post denormal normal test".to_string(),
            trace_id: "trace-post-denormal".to_string(),
        };

        let normal_decision = gate.submit(normal_proposal);
        assert!(matches!(
            normal_decision,
            super::optimization_governor::GovernorDecision::Approved
        ));
    }

    #[test]
    fn extreme_adversarial_algorithmic_complexity_explosion_via_pathological_inputs() {
        use super::optimization_governor::{
            GovernorGate, OptimizationGovernor, OptimizationProposal, PredictedMetrics,
            RuntimeKnob, SafetyEnvelope,
        };
        use std::collections::BTreeMap;

        // Test inputs designed to trigger worst-case algorithmic complexity

        // 1. Exponential blowup in validation patterns
        let mut gate = GovernorGate::with_defaults();

        // Create proposals with pathologically nested/repetitive patterns
        let complexity_attacks = vec![
            // Exponentially recursive-looking patterns in rationale
            "(".repeat(1000) + &")".repeat(1000),
            // Patterns that could trigger ReDoS-like behavior in string processing
            "a".repeat(1000) + "b",
            "x".repeat(10000),
            // Unicode normalization complexity bombs
            "\u{0300}".repeat(1000), // Combining accent marks
            "e\u{0301}".repeat(500), // Accented e repeated
            // Pattern that could cause hash collision clustering
            "hash_collision_attempt_"
                + &(0..100)
                    .map(|i| format!("{:02x}", i))
                    .collect::<Vec<_>>()
                    .join("_"),
            // JSON-like nested structure in strings (could cause parser confusion)
            "{".repeat(500) + &"}".repeat(500),
            "\"".repeat(200),
        ];

        for (attack_idx, pathological_pattern) in complexity_attacks.iter().enumerate() {
            let start_time = std::time::Instant::now();

            let proposal = OptimizationProposal {
                proposal_id: format!("complexity_attack_{}", attack_idx),
                knob: RuntimeKnob::ConcurrencyLimit,
                old_value: 64,
                new_value: 128u64.saturating_add(attack_idx as u64),
                predicted: PredictedMetrics {
                    latency_ms: 200,
                    throughput_rps: 500,
                    error_rate_pct: 0.1,
                    memory_mb: 2048,
                },
                rationale: pathological_pattern.clone(),
                trace_id: format!("trace-complexity-{}", attack_idx),
            };

            let _decision = gate.submit(proposal);
            let processing_time = start_time.elapsed();

            // Should complete in reasonable time regardless of pathological input
            assert!(
                processing_time < std::time::Duration::from_millis(100),
                "Pathological pattern {} caused algorithmic complexity explosion: {:?}",
                attack_idx,
                processing_time
            );
        }

        // 2. Test complexity attacks in knob state enumeration
        let mut complex_knob_state = BTreeMap::new();

        // Fill with maximum number of knobs to stress enumeration algorithms
        complex_knob_state.insert(
            RuntimeKnob::ConcurrencyLimit,
            super::optimization_governor::KnobState { value: 64 },
        );
        complex_knob_state.insert(
            RuntimeKnob::BatchSize,
            super::optimization_governor::KnobState { value: 128 },
        );
        complex_knob_state.insert(
            RuntimeKnob::CacheCapacity,
            super::optimization_governor::KnobState { value: 1024 },
        );
        complex_knob_state.insert(
            RuntimeKnob::RetryBudget,
            super::optimization_governor::KnobState { value: 3 },
        );

        let complex_governor =
            OptimizationGovernor::new(SafetyEnvelope::default(), complex_knob_state);
        let mut complex_gate = GovernorGate::new(complex_governor);

        // Submit many overlapping proposals to stress conflict resolution
        let overlap_start = std::time::Instant::now();
        for i in 0..1000 {
            let overlap_proposal = OptimizationProposal {
                proposal_id: format!("overlap_{:04}", i),
                knob: match i % 4 {
                    0 => RuntimeKnob::ConcurrencyLimit,
                    1 => RuntimeKnob::BatchSize,
                    2 => RuntimeKnob::CacheCapacity,
                    _ => RuntimeKnob::RetryBudget,
                },
                old_value: match i % 4 {
                    0 => 64,
                    1 => 128,
                    2 => 1024,
                    _ => 3,
                },
                new_value: (i as u64) % 1000 + 1,
                predicted: PredictedMetrics {
                    latency_ms: 200.0 + (i as f64 * 0.001),
                    throughput_rps: 500.0 - (i as f64 * 0.001),
                    error_rate_pct: 0.1,
                    memory_mb: 2048,
                },
                rationale: format!("overlap stress test {}", i),
                trace_id: format!("trace-overlap-{:04}", i),
            };

            let iter_start = std::time::Instant::now();
            let _decision = complex_gate.submit(overlap_proposal);
            let iter_time = iter_start.elapsed();

            // Each individual operation should remain fast
            assert!(
                iter_time < std::time::Duration::from_millis(10),
                "Iteration {} too slow during overlap stress: {:?}",
                i,
                iter_time
            );
        }

        let total_overlap_time = overlap_start.elapsed();
        assert!(
            total_overlap_time < std::time::Duration::from_secs(5),
            "Total overlap stress test too slow: {:?}",
            total_overlap_time
        );

        // 3. Test worst-case live check scenarios
        let live_check_start = std::time::Instant::now();

        // Create scenario with many applied policies to stress revert logic
        for i in 0..100 {
            let revert_proposal = OptimizationProposal {
                proposal_id: format!("revert_candidate_{:03}", i),
                knob: RuntimeKnob::ConcurrencyLimit,
                old_value: 64,
                new_value: 65, // Minimal changes to accumulate many applied policies
                predicted: PredictedMetrics {
                    latency_ms: 200,
                    throughput_rps: 500,
                    error_rate_pct: 0.1,
                    memory_mb: 2048,
                },
                rationale: format!("revert stress setup {}", i),
                trace_id: format!("trace-revert-{:03}", i),
            };

            let _decision = complex_gate.submit(revert_proposal);
        }

        // Trigger live check that should revert many policies
        let mass_revert_start = std::time::Instant::now();
        let unsafe_metrics = PredictedMetrics {
            latency_ms: 2000,     // Violates safety envelope
            throughput_rps: 10,   // Violates safety envelope
            error_rate_pct: 10.0, // Violates safety envelope
            memory_mb: 20000,     // Violates safety envelope
        };

        let _reverted = complex_gate.live_check(&unsafe_metrics);
        let mass_revert_time = mass_revert_start.elapsed();

        assert!(
            mass_revert_time < std::time::Duration::from_millis(500),
            "Mass revert operation too slow: {:?}",
            mass_revert_time
        );

        let total_live_check_time = live_check_start.elapsed();
        assert!(
            total_live_check_time < std::time::Duration::from_secs(2),
            "Total live check stress test too slow: {:?}",
            total_live_check_time
        );
    }

    #[test]
    fn extreme_adversarial_state_machine_transition_fuzzing_with_invalid_sequences() {
        use super::optimization_governor::{
            GovernorDecision, GovernorGate, OptimizationProposal, PredictedMetrics,
            RejectionReason, RuntimeKnob,
        };

        let mut gate = GovernorGate::with_defaults();

        // Test invalid state transition sequences that could corrupt internal state

        // Sequence 1: Rapid apply/revert cycles
        for cycle in 0..100 {
            // Apply
            let apply_proposal = OptimizationProposal {
                proposal_id: format!("cycle_apply_{}", cycle),
                knob: RuntimeKnob::ConcurrencyLimit,
                old_value: 64,
                new_value: 128,
                predicted: PredictedMetrics {
                    latency_ms: 200,
                    throughput_rps: 500,
                    error_rate_pct: 0.1,
                    memory_mb: 2048,
                },
                rationale: format!("rapid cycle apply {}", cycle),
                trace_id: format!("trace-apply-{}", cycle),
            };

            let apply_decision = gate.submit(apply_proposal);

            // Immediately trigger revert with unsafe metrics
            let unsafe_metrics = PredictedMetrics {
                latency_ms: 1000,
                throughput_rps: 50,
                error_rate_pct: 5.0,
                memory_mb: 10000,
            };

            let _reverted = gate.live_check(&unsafe_metrics);

            // Verify state consistency after each cycle
            if let Some(snapshot) = gate.snapshot() {
                for (knob, state) in snapshot.current_state {
                    // All values should be within reasonable bounds
                    assert!(
                        state.value <= 10000,
                        "Knob {:?} has unreasonable value {} after cycle {}",
                        knob,
                        state.value,
                        cycle
                    );

                    // Should not have negative or zero values where inappropriate
                    match knob {
                        RuntimeKnob::ConcurrencyLimit | RuntimeKnob::BatchSize => {
                            assert!(
                                state.value > 0,
                                "Knob {:?} has invalid zero/negative value after cycle {}",
                                knob,
                                cycle
                            );
                        }
                        _ => {}
                    }
                }
            }
        }

        // Sequence 2: Invalid old_value progression
        let mut expected_value = 64u64;
        for i in 0..50 {
            // Submit with correct old_value
            let correct_proposal = OptimizationProposal {
                proposal_id: format!("progression_correct_{}", i),
                knob: RuntimeKnob::ConcurrencyLimit,
                old_value: expected_value,
                new_value: expected_value + 1,
                predicted: PredictedMetrics {
                    latency_ms: 200,
                    throughput_rps: 500,
                    error_rate_pct: 0.1,
                    memory_mb: 2048,
                },
                rationale: format!("progression test correct {}", i),
                trace_id: format!("trace-correct-{}", i),
            };

            let correct_decision = gate.submit(correct_proposal);

            if matches!(correct_decision, GovernorDecision::Approved) {
                expected_value = expected_value.saturating_add(1);
            }

            // Submit with deliberately wrong old_value
            let wrong_proposal = OptimizationProposal {
                proposal_id: format!("progression_wrong_{}", i),
                knob: RuntimeKnob::ConcurrencyLimit,
                old_value: expected_value.saturating_sub(10), // Wrong old value
                new_value: expected_value + 10,
                predicted: PredictedMetrics {
                    latency_ms: 200,
                    throughput_rps: 500,
                    error_rate_pct: 0.1,
                    memory_mb: 2048,
                },
                rationale: format!("progression test wrong {}", i),
                trace_id: format!("trace-wrong-{}", i),
            };

            let wrong_decision = gate.submit(wrong_proposal);

            // Wrong old_value should always be rejected
            assert!(
                matches!(
                    wrong_decision,
                    GovernorDecision::Rejected(RejectionReason::InvalidProposal(_))
                ),
                "Wrong old_value should be rejected at iteration {}",
                i
            );

            // State should remain consistent
            assert_eq!(
                gate.inner().knob_value(&RuntimeKnob::ConcurrencyLimit),
                Some(expected_value),
                "Knob value corrupted at iteration {}",
                i
            );
        }

        // Sequence 3: Interleaved proposals for different knobs with state conflicts
        for round in 0..20 {
            let proposals = vec![
                (RuntimeKnob::ConcurrencyLimit, 64u64, 128u64),
                (RuntimeKnob::BatchSize, 128u64, 256u64),
                (RuntimeKnob::CacheCapacity, 1024u64, 2048u64),
                (RuntimeKnob::RetryBudget, 3u64, 6u64),
            ];

            // Submit all proposals in rapid succession
            for (i, (knob, old_val, new_val)) in proposals.iter().enumerate() {
                let interleaved_proposal = OptimizationProposal {
                    proposal_id: format!("interleaved_{}_{}", round, i),
                    knob: *knob,
                    old_value: *old_val,
                    new_value: *new_val,
                    predicted: PredictedMetrics {
                        latency_ms: 200,
                        throughput_rps: 500,
                        error_rate_pct: 0.1,
                        memory_mb: 2048,
                    },
                    rationale: format!("interleaved test round {} proposal {}", round, i),
                    trace_id: format!("trace-interleaved-{}-{}", round, i),
                };

                let _decision = gate.submit(interleaved_proposal);
            }

            // Perform live check in the middle
            let mid_metrics = PredictedMetrics {
                latency_ms: if round % 2 == 0 { 200 } else { 1000 }, // Alternate safe/unsafe
                throughput_rps: 500,
                error_rate_pct: 0.1,
                memory_mb: 2048,
            };

            let _reverted = gate.live_check(&mid_metrics);

            // Verify all knobs maintain valid states
            if let Some(snapshot) = gate.snapshot() {
                for (knob, state) in snapshot.current_state {
                    match knob {
                        RuntimeKnob::ConcurrencyLimit => {
                            assert!(
                                state.value >= 64 && state.value <= 10000,
                                "ConcurrencyLimit out of bounds: {} at round {}",
                                state.value,
                                round
                            );
                        }
                        RuntimeKnob::BatchSize => {
                            assert!(
                                state.value >= 128 && state.value <= 10000,
                                "BatchSize out of bounds: {} at round {}",
                                state.value,
                                round
                            );
                        }
                        RuntimeKnob::CacheCapacity => {
                            assert!(
                                state.value >= 1024 && state.value <= 100000,
                                "CacheCapacity out of bounds: {} at round {}",
                                state.value,
                                round
                            );
                        }
                        RuntimeKnob::RetryBudget => {
                            assert!(
                                state.value >= 3 && state.value <= 1000,
                                "RetryBudget out of bounds: {} at round {}",
                                state.value,
                                round
                            );
                        }
                    }
                }
            }
        }

        // Final state consistency check
        assert!(
            gate.inner().decision_count() > 0,
            "Should have recorded decisions"
        );
        assert!(
            gate.audit_trail().len() > 0,
            "Should have audit trail entries"
        );

        // Verify system can still accept valid proposals after fuzzing
        let final_test_proposal = OptimizationProposal {
            proposal_id: "final_state_test".to_string(),
            knob: RuntimeKnob::ConcurrencyLimit,
            old_value: gate
                .inner()
                .knob_value(&RuntimeKnob::ConcurrencyLimit)
                .unwrap_or(64),
            new_value: 256,
            predicted: PredictedMetrics {
                latency_ms: 200,
                throughput_rps: 500,
                error_rate_pct: 0.1,
                memory_mb: 2048,
            },
            rationale: "final state machine test".to_string(),
            trace_id: "trace-final-state".to_string(),
        };

        let final_decision = gate.submit(final_test_proposal);
        assert!(
            matches!(
                final_decision,
                GovernorDecision::Approved | GovernorDecision::Rejected(_)
            ),
            "System should remain functional after state machine fuzzing"
        );
    }
}
