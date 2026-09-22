#![cfg(feature = "differential")]

use ed25519_dalek::{Signer, SigningKey};
use frankenengine_node::tools::counterfactual_replay::{
    CounterfactualReplayEngine, PolicyConfig, to_canonical_json,
};
use frankenengine_node::tools::replay_bundle::{
    EventType, RawEvent, ReplayBundle, generate_replay_bundle,
};
use frankenengine_verifier_sdk::bundle::BundleError;
use frankenengine_verifier_sdk::counterfactual::{
    CounterfactualReceiptError, verify_counterfactual_receipt,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn counterfactual_receipt_roundtrip_and_tamper_detection() -> TestResult {
    let baseline_bundle = fixture_bundle()?;
    let engine = CounterfactualReplayEngine::default();
    let baseline_policy = PolicyConfig::from_bundle(&baseline_bundle);
    let alternate_policy = PolicyConfig {
        policy_name: "strict".to_string(),
        quarantine_threshold: 70,
        observe_threshold: 45,
        degraded_mode_bias: 20,
    };
    let output =
        engine.replay_with_baseline(&baseline_bundle, &baseline_policy, &alternate_policy)?;
    let signing_key = SigningKey::from_bytes(&[17_u8; 32]);
    let canonical_output = to_canonical_json(&output)?;
    let signature = signing_key.sign(canonical_output.as_bytes());
    let signature_bytes = signature.to_bytes();

    verify_counterfactual_receipt(
        &baseline_bundle,
        &output,
        &signing_key.verifying_key(),
        &signature_bytes,
    )?;

    let mut tampered_output = output.clone();
    tampered_output.summary_statistics.changed_decisions = tampered_output
        .summary_statistics
        .changed_decisions
        .saturating_add(1);

    let Err(error) = verify_counterfactual_receipt(
        &baseline_bundle,
        &tampered_output,
        &signing_key.verifying_key(),
        &signature_bytes,
    ) else {
        return Err("tampered counterfactual output unexpectedly verified".into());
    };
    if error != CounterfactualReceiptError::Signature(BundleError::Ed25519SignatureInvalid) {
        return Err(format!("unexpected tamper verification error: {error}").into());
    }

    Ok(())
}

fn fixture_bundle() -> TestResult<ReplayBundle> {
    let events = vec![
        RawEvent::new(
            "2026-02-20T12:00:00.000001Z",
            EventType::ExternalSignal,
            serde_json::json!({
                "detector": "counterfactual-verifier-fixture",
                "severity": "high",
                "signal": "extension-authority-escalation"
            }),
        )
        .with_state_snapshot(serde_json::json!({
            "epoch": 91_u64,
            "active_substrates": ["node", "bun", "asupersync"],
            "active_policies": ["extension-quarantine", "counterfactual-replay"]
        }))
        .with_policy_version("counterfactual-baseline-2026-04"),
        RawEvent::new(
            "2026-02-20T12:00:00.000250Z",
            EventType::PolicyEval,
            serde_json::json!({
                "confidence": 68_u64,
                "decision": "observe",
                "rule_id": "policy.counterfactual.recheck"
            }),
        )
        .with_causal_parent(1),
        RawEvent::new(
            "2026-02-20T12:00:00.000500Z",
            EventType::OperatorAction,
            serde_json::json!({
                "action": "continue-with-guardrail",
                "confidence": 46_u64,
                "degraded_mode": true,
                "result": "accepted"
            }),
        )
        .with_causal_parent(2),
    ];

    Ok(generate_replay_bundle("INC-SDK-CF-VERIFY-001", &events)?)
}
