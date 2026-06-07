use frankenengine_node::storage::cas::content_hash;
use frankenengine_node::tools::counterfactual_replay::{
    CounterfactualReplayEngine, CounterfactualResult, PolicyConfig, to_canonical_json,
};
use frankenengine_node::tools::replay_bundle::{
    EventType, RawEvent, ReplayBundle, ReplayBundleSigningMaterial, generate_replay_bundle,
    read_bundle_from_path_with_trusted_key, sign_replay_bundle,
    write_bundle_to_path_with_trusted_key,
};
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Create test bundle using real file I/O roundtrip to exercise serialization path
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

    // Generate bundle in memory
    let mut bundle = generate_replay_bundle("INC-CF-MATRIX-001", &events)?;

    // Sign the bundle for file I/O operations
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let signing_material = ReplayBundleSigningMaterial {
        signing_key: &signing_key,
        key_source: "test-counterfactual-matrix",
        signing_identity: "counterfactual-policy-matrix-test",
    };
    sign_replay_bundle(&mut bundle, &signing_material)?;

    // Create temporary workspace for real file I/O
    let workspace = TempDir::new()?;
    let bundle_path = workspace.path().join("counterfactual_matrix_bundle.json");

    // Derive trusted key ID for file operations
    let trusted_key_id =
        frankenengine_node::supply_chain::artifact_signing::KeyId::from_verifying_key(
            &signing_key.verifying_key(),
        )
        .to_string();

    // Write bundle to real file system
    write_bundle_to_path_with_trusted_key(&bundle, &bundle_path, &trusted_key_id)?;

    // Read bundle back from file system - this exercises the full serialization roundtrip
    let file_loaded_bundle =
        read_bundle_from_path_with_trusted_key(&bundle_path, Some(&trusted_key_id))?;

    Ok(file_loaded_bundle)
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
    let first_json = String::from_utf8(first_bytes)?;
    assert!(
        !first_json.contains("recorded_effects"),
        "no-effect bundles must not grow empty recorded_effects fields"
    );
    assert!(
        !first_json.contains("effect_diffs"),
        "no-effect bundles must not grow empty effect_diffs fields"
    );

    Ok(())
}

#[test]
fn counterfactual_replay_reports_recorded_host_effect_policy_diff() -> TestResult {
    let pre_state_hash = content_hash(b"socket-pool-before").as_str().to_string();
    let args_hash = content_hash(br#"{"url":"https://api.example.test/audit"}"#)
        .as_str()
        .to_string();
    let result_hash = content_hash(b"HTTP/1.1 200 OK\nbody").as_str().to_string();
    let post_state_hash = content_hash(b"socket-pool-after").as_str().to_string();
    let events = vec![
        RawEvent::new(
            "2026-02-20T13:00:00.000001Z",
            EventType::PolicyEval,
            serde_json::json!({
                "confidence": 60_u64,
                "decision": "observe",
                "rule_id": "policy.http.audit",
                "effect_receipts": [{
                    "seq": 7_u64,
                    "effect_kind": "http_request",
                    "capability_ref": "cap:http.audit",
                    "pre_state_hash": pre_state_hash,
                    "args_hash": args_hash,
                    "result_hash": result_hash,
                    "post_state_hash": post_state_hash,
                    "policy_outcome": {
                        "outcome": "allowed",
                        "capability_ref": "cap:http.audit"
                    }
                }]
            }),
        )
        .with_policy_version("counterfactual-real-io-baseline"),
    ];
    let bundle = generate_replay_bundle("INC-CF-REAL-IO-001", &events)?;
    let engine = CounterfactualReplayEngine::default();
    let baseline = PolicyConfig::from_bundle(&bundle);
    let strict = strict_policy();

    let result = replay_profile(&engine, &bundle, &baseline, &strict)?;

    assert_eq!(result.summary_statistics.total_decisions, 1);
    assert_eq!(result.summary_statistics.changed_decisions, 1);
    let original_outcome = result.original_outcomes.first().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::Other, "missing original outcome")
    })?;
    let original_effect = original_outcome
        .recorded_effects
        .first()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "missing recorded effect"))?;
    assert_eq!(original_effect.effect_kind, "http_request");
    assert_eq!(original_effect.capability_ref, "cap:http.audit");
    assert_eq!(original_effect.recorded_policy_decision, "allow");
    let counterfactual_outcome = result.counterfactual_outcomes.first().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::Other, "missing counterfactual outcome")
    })?;
    assert!(
        counterfactual_outcome
            .rationale
            .contains("recorded_effects=1")
    );

    let divergence = result
        .divergence_points
        .iter()
        .find(|record| !record.effect_diffs.is_empty())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "strict counterfactual should include effect-level diff",
            )
        })?;
    let effect_diff = divergence
        .effect_diffs
        .first()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "missing effect diff"))?;
    assert_eq!(effect_diff.sequence_number, 7);
    assert_eq!(effect_diff.effect_kind, "http_request");
    assert_eq!(effect_diff.capability_ref, "cap:http.audit");
    assert_eq!(effect_diff.original_effect_decision, "allow");
    assert_eq!(effect_diff.counterfactual_effect_decision, "deny");
    assert!(original_effect.result_hash.is_some());
    assert_eq!(
        effect_diff.result_hash.as_deref(),
        original_effect.result_hash.as_deref()
    );

    Ok(())
}
