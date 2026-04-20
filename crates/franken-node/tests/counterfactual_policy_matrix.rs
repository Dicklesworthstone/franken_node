use frankenengine_node::tools::counterfactual_replay::{
    CounterfactualReplayEngine, CounterfactualResult, PolicyConfig, to_canonical_json,
};
use frankenengine_node::tools::replay_bundle::{
    EventType, RawEvent, ReplayBundle, generate_replay_bundle,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn fixture_bundle() -> TestResult<ReplayBundle> {
    let events = vec![
        RawEvent::new(
            "2026-02-20T12:00:00.000001Z",
            EventType::ExternalSignal,
            serde_json::json!({
                "detector": "extension-reputation",
                "severity": "high",
                "signal": "new-package-authority-escalation",
                "source": "federated-risk-feed"
            }),
        )
        .with_state_snapshot(serde_json::json!({
            "epoch": 72_u64,
            "runtime_profile": "balanced",
            "active_substrates": ["node", "bun", "asupersync"],
            "active_policies": ["extension-quarantine", "federated-reputation"]
        }))
        .with_policy_version("counterfactual-baseline-2026-02"),
        RawEvent::new(
            "2026-02-20T12:00:00.000250Z",
            EventType::PolicyEval,
            serde_json::json!({
                "confidence": 88_u64,
                "decision": "quarantine",
                "rule_id": "policy.extension.high-impact-receipt"
            }),
        )
        .with_causal_parent(1),
        RawEvent::new(
            "2026-02-20T12:00:00.000500Z",
            EventType::ExternalSignal,
            serde_json::json!({
                "confidence": 62_u64,
                "severity": "medium",
                "signal": "cross-substrate-drift",
                "substrate": "bun"
            }),
        )
        .with_causal_parent(2),
        RawEvent::new(
            "2026-02-20T12:00:00.000750Z",
            EventType::PolicyEval,
            serde_json::json!({
                "confidence": 68_u64,
                "decision": "observe",
                "rule_id": "policy.federation.recheck"
            }),
        )
        .with_causal_parent(3),
        RawEvent::new(
            "2026-02-20T12:00:00.001000Z",
            EventType::OperatorAction,
            serde_json::json!({
                "action": "continue-with-guardrail",
                "confidence": 46_u64,
                "degraded_mode": true,
                "result": "accepted"
            }),
        )
        .with_causal_parent(4),
    ];

    Ok(generate_replay_bundle("INC-CF-MATRIX-001", &events)?)
}

fn strict_policy() -> PolicyConfig {
    PolicyConfig {
        policy_name: "strict".to_string(),
        quarantine_threshold: 70,
        observe_threshold: 45,
        degraded_mode_bias: 20,
    }
}

fn balanced_policy(baseline: &PolicyConfig) -> PolicyConfig {
    PolicyConfig {
        policy_name: "balanced".to_string(),
        ..baseline.clone()
    }
}

fn legacy_risky_policy() -> PolicyConfig {
    PolicyConfig {
        policy_name: "legacy-risky".to_string(),
        quarantine_threshold: 95,
        observe_threshold: 75,
        degraded_mode_bias: 0,
    }
}

fn replay_profile(
    engine: &CounterfactualReplayEngine,
    bundle: &ReplayBundle,
    baseline: &PolicyConfig,
    policy: &PolicyConfig,
) -> TestResult<CounterfactualResult> {
    Ok(engine.replay_with_baseline(bundle, baseline, policy)?)
}

#[test]
fn counterfactual_profile_matrix_bounds_and_monotone_severity_delta() -> TestResult {
    let bundle = fixture_bundle()?;
    let engine = CounterfactualReplayEngine::default();
    let baseline = PolicyConfig::from_bundle(&bundle);
    let strict = strict_policy();
    let balanced = balanced_policy(&baseline);
    let legacy_risky = legacy_risky_policy();

    let strict_result = replay_profile(&engine, &bundle, &baseline, &strict)?;
    let balanced_result = replay_profile(&engine, &bundle, &baseline, &balanced)?;
    let legacy_risky_result = replay_profile(&engine, &bundle, &baseline, &legacy_risky)?;
    let profile_results = [
        (&strict, &strict_result),
        (&balanced, &balanced_result),
        (&legacy_risky, &legacy_risky_result),
    ];

    for (policy, result) in profile_results {
        let total_decisions = result.summary_statistics.total_decisions;
        let changed_decisions = result.summary_statistics.changed_decisions;

        assert_eq!(
            total_decisions,
            bundle.timeline.len(),
            "{} must evaluate every fixture event",
            policy.policy_name
        );
        assert!(
            changed_decisions <= total_decisions,
            "{} changed_decisions must be bounded by total_decisions",
            policy.policy_name
        );
        assert_eq!(
            changed_decisions,
            result.divergence_points.len(),
            "{} changed_decisions must match divergence records",
            policy.policy_name
        );
    }

    assert!(
        strict_result.summary_statistics.changed_decisions > 0,
        "strict profile should exercise at least one policy divergence"
    );
    assert!(
        legacy_risky_result.summary_statistics.changed_decisions > 0,
        "legacy-risky profile should exercise at least one policy divergence"
    );
    assert!(
        strict_result.summary_statistics.severity_delta
            <= balanced_result.summary_statistics.severity_delta,
        "strict severity_delta must be no worse than balanced"
    );
    assert!(
        balanced_result.summary_statistics.severity_delta
            <= legacy_risky_result.summary_statistics.severity_delta,
        "balanced severity_delta must be no worse than legacy-risky"
    );

    Ok(())
}

#[test]
fn counterfactual_replay_is_byte_identical_for_same_bundle_and_policy() -> TestResult {
    let bundle = fixture_bundle()?;
    let engine = CounterfactualReplayEngine::default();
    let baseline = PolicyConfig::from_bundle(&bundle);
    let legacy_risky = legacy_risky_policy();

    let first = replay_profile(&engine, &bundle, &baseline, &legacy_risky)?;
    let second = replay_profile(&engine, &bundle, &baseline, &legacy_risky)?;

    let first_bytes = to_canonical_json(&first)?.into_bytes();
    let second_bytes = to_canonical_json(&second)?.into_bytes();

    assert_eq!(first_bytes, second_bytes);

    Ok(())
}
