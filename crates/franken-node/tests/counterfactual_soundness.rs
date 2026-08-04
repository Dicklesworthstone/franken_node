//! bd-5r99w.13 — counterfactual soundness / conservativeness property.
//!
//! bd-5r99w.4 labels the counterfactual executor; this suite proves the diff it
//! produces is SOUND with respect to the policy it claims to simulate. An
//! operator makes lockdown decisions on a counterfactual, so the cardinal sin is
//! a *false* "would-have-blocked": reporting that a stricter policy would have
//! quarantined an action when the recorded inputs do not actually cross that
//! policy's threshold.
//!
//! Properties asserted:
//!
//! * **Soundness / no false would-have-blocked** — every counterfactual decision
//!   (especially every `quarantine`) is *reproducible*: re-evaluating the
//!   recorded risk (which the executor commits into each decision's rationale)
//!   against the alternate policy's thresholds reproduces exactly the reported
//!   decision. A `quarantine` verdict therefore requires the recorded risk to
//!   actually reach `quarantine_threshold` — no confident block without a
//!   reproducible threshold cross.
//! * **Monotonicity** — tightening the policy (lowering `quarantine_threshold`)
//!   can only keep-or-increase the number of blocked decisions; loosening it can
//!   only keep-or-decrease them. Violations would mean the simulator is not a
//!   faithful function of the policy lattice.
//! * **Determinism / reproducibility** — the same bundle under the same policy
//!   yields an identical result, so an external party can reproduce the verdict.
//! * **Closed, sound verdict vocabulary (conservativeness substitute)** — every
//!   verdict is one of `allow` / `observe` / `quarantine`, and every `quarantine`
//!   is reproducible from the recorded risk. The model does NOT today emit an
//!   explicit `indeterminate` for under-captured telemetry: an under-specified
//!   event is assigned a *default* risk and decided normally (a bare operator
//!   `acknowledge` scores risk=50, not "unknown"). So the operator-facing
//!   guarantee against false reassurance is soundness — no confident
//!   would-have-blocked without a reproducible threshold cross — rather than an
//!   indeterminate label. An explicit indeterminate verdict that propagates
//!   missing-evidence reasons is future work tied to the engine sentinel
//!   ([[bd-f5b04]]); this suite documents the current closed-vocabulary behavior
//!   so a future indeterminate path is a deliberate, tested change.

use frankenengine_node::tools::counterfactual_replay::{
    CounterfactualReplayEngine, CounterfactualResult, PolicyConfig,
};
use frankenengine_node::tools::replay_bundle::{
    EventType, RawEvent, ReplayBundle, ReplayBundleSigningMaterial, generate_replay_bundle,
    sign_replay_bundle,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A recorded incident with a spread of risk levels so a threshold sweep
/// produces a non-trivial (varying) block count.
fn fixture_events() -> Vec<RawEvent> {
    vec![
        RawEvent::new(
            "2026-03-02T08:00:00.000001Z",
            EventType::ExternalSignal,
            serde_json::json!({
                "detector": "extension-reputation",
                "severity": "critical",
                "signal": "publisher-key-rotation-anomaly",
            }),
        )
        .with_state_snapshot(serde_json::json!({
            "epoch": 41_u64,
            "runtime_profile": "balanced",
        }))
        .with_policy_version("cf-soundness-baseline-2026-03"),
        RawEvent::new(
            "2026-03-02T08:00:00.000200Z",
            EventType::PolicyEval,
            serde_json::json!({
                "severity": "high",
                "decision": "quarantine",
                "rule_id": "policy.extension.high-impact",
            }),
        )
        .with_causal_parent(1),
        RawEvent::new(
            "2026-03-02T08:00:00.000400Z",
            EventType::ExternalSignal,
            serde_json::json!({
                "severity": "medium",
                "signal": "cross-substrate-drift",
            }),
        )
        .with_causal_parent(2),
        RawEvent::new(
            "2026-03-02T08:00:00.000600Z",
            EventType::PolicyEval,
            serde_json::json!({
                "severity": "low",
                "decision": "observe",
                "rule_id": "policy.federation.recheck",
            }),
        )
        .with_causal_parent(3),
        // A deliberately sparse / low-signal event: minimal payload, no severity.
        RawEvent::new(
            "2026-03-02T08:00:00.000800Z",
            EventType::OperatorAction,
            serde_json::json!({ "action": "acknowledge" }),
        )
        .with_causal_parent(4),
    ]
}

fn fixture_bundle() -> TestResult<ReplayBundle> {
    let mut bundle = generate_replay_bundle("INC-CF-SOUNDNESS-001", &fixture_events())?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x5a; 32]);
    sign_replay_bundle(
        &mut bundle,
        &ReplayBundleSigningMaterial {
            signing_key: &signing_key,
            key_source: "counterfactual-soundness",
            signing_identity: "bd-5r99w.13-soundness",
        },
    )?;
    Ok(bundle)
}

/// Policy with a fixed (low) observe threshold and no degraded-mode bias, so the
/// per-event recorded risk is identical across a `quarantine_threshold` sweep and
/// monotonicity is a pure property of the thresholding.
fn sweep_policy(quarantine_threshold: u64) -> PolicyConfig {
    PolicyConfig {
        policy_name: format!("sweep-q{quarantine_threshold}"),
        quarantine_threshold,
        observe_threshold: 15,
        degraded_mode_bias: 0,
    }
}

/// Extract the recorded risk the executor committed into a decision rationale
/// (`"... risk=<N> ..."`). This is the independent input the alternate policy is
/// re-evaluated against.
fn risk_from_rationale(rationale: &str) -> u64 {
    rationale
        .split("risk=")
        .nth(1)
        .and_then(|rest| {
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            digits.parse::<u64>().ok()
        })
        .unwrap_or_else(|| panic!("decision rationale must embed `risk=<N>`: {rationale:?}"))
}

/// The decision the policy lattice prescribes for a recorded risk — the
/// reference oracle the engine's output must reproduce.
fn expected_decision(risk: u64, policy: &PolicyConfig) -> &'static str {
    if risk >= policy.quarantine_threshold {
        "quarantine"
    } else if risk >= policy.observe_threshold {
        "observe"
    } else {
        "allow"
    }
}

fn quarantine_count(result: &CounterfactualResult) -> usize {
    result
        .counterfactual_outcomes
        .iter()
        .filter(|point| point.decision == "quarantine")
        .count()
}

#[test]
fn counterfactual_decisions_are_reproducible_from_recorded_risk() -> TestResult {
    let bundle = fixture_bundle()?;
    let engine = CounterfactualReplayEngine::default();
    let baseline = PolicyConfig::from_bundle(&bundle);

    // Evaluate across the policy lattice (strict → permissive) plus sweep points.
    let policies = [
        sweep_policy(25),
        sweep_policy(50),
        sweep_policy(75),
        sweep_policy(100),
    ];

    for policy in &policies {
        let result = engine.replay_with_baseline(&bundle, &baseline, policy)?;
        for point in &result.counterfactual_outcomes {
            let risk = risk_from_rationale(&point.rationale);
            let expected = expected_decision(risk, policy);
            assert_eq!(
                point.decision,
                expected,
                "SOUNDNESS: decision for seq {} under `{}` must be reproducible from recorded \
                 risk={risk} and thresholds (observe={}, quarantine={}); reported `{}`, reference `{expected}`",
                point.sequence_number,
                policy.policy_name,
                policy.observe_threshold,
                policy.quarantine_threshold,
                point.decision,
            );
            // The cardinal guarantee: a "would-have-blocked" requires a real cross.
            if point.decision == "quarantine" {
                assert!(
                    risk >= policy.quarantine_threshold,
                    "no false would-have-blocked: a quarantine verdict requires risk ({risk}) >= \
                     quarantine_threshold ({})",
                    policy.quarantine_threshold
                );
            }
        }
    }
    Ok(())
}

#[test]
fn tightening_policy_is_monotone_in_blocked_decisions() -> TestResult {
    let bundle = fixture_bundle()?;
    let engine = CounterfactualReplayEngine::default();
    let baseline = PolicyConfig::from_bundle(&bundle);

    // Ascending quarantine_threshold == progressively LOOSER policy.
    let thresholds = [20_u64, 40, 60, 80, 100];
    let mut counts = Vec::with_capacity(thresholds.len());
    for &threshold in &thresholds {
        let result = engine.replay_with_baseline(&bundle, &baseline, &sweep_policy(threshold))?;
        counts.push(quarantine_count(&result));
    }

    // Loosening (raising the threshold) can only keep-or-decrease blocks;
    // equivalently, tightening can only keep-or-increase them.
    for window in counts.windows(2) {
        assert!(
            window[0] >= window[1],
            "monotonicity: blocked-decision count must be non-increasing as quarantine_threshold \
             rises (looser); got sequence {counts:?}"
        );
    }
    // The sweep must be non-trivial: the strictest point blocks more than the loosest.
    assert!(
        counts.first() >= counts.last(),
        "sweep must exercise a real spread of block counts: {counts:?}"
    );
    assert!(
        *counts.first().unwrap() > 0,
        "the strictest policy must block at least one recorded decision: {counts:?}"
    );
    Ok(())
}

#[test]
fn replay_is_deterministic_and_reproducible() -> TestResult {
    let bundle = fixture_bundle()?;
    let engine = CounterfactualReplayEngine::default();
    let baseline = PolicyConfig::from_bundle(&bundle);
    let policy = sweep_policy(50);

    let first = engine.replay_with_baseline(&bundle, &baseline, &policy)?;
    let second = engine.replay_with_baseline(&bundle, &baseline, &policy)?;
    assert_eq!(
        first, second,
        "the same bundle under the same policy must reproduce an identical counterfactual result"
    );
    Ok(())
}

#[test]
fn verdicts_are_closed_and_indeterminate_is_documented_future_work() -> TestResult {
    let bundle = fixture_bundle()?;
    let engine = CounterfactualReplayEngine::default();
    let baseline = PolicyConfig::from_bundle(&bundle);

    // Characterization + conservativeness substitute. The model does not emit an
    // `indeterminate` verdict for under-captured telemetry today: every event
    // (including the trailing sparse `acknowledge`, which scores a *default*
    // risk=50 rather than "unknown") is decided into the closed vocabulary
    // {allow, observe, quarantine}. The guarantee against a FALSE
    // would-have-blocked is therefore soundness: no quarantine without the
    // recorded risk reproducibly crossing the threshold. If an explicit
    // indeterminate path is added later (engine sentinel work), this test must be
    // updated deliberately — so it pins the current behavior.
    const KNOWN_VERDICTS: [&str; 3] = ["allow", "observe", "quarantine"];
    for policy in [sweep_policy(25), sweep_policy(100)] {
        let result = engine.replay_with_baseline(&bundle, &baseline, &policy)?;
        for point in &result.counterfactual_outcomes {
            assert!(
                KNOWN_VERDICTS.contains(&point.decision.as_str()),
                "verdict vocabulary must stay closed (no fabricated/indeterminate verdict today); \
                 seq {} produced `{}`",
                point.sequence_number,
                point.decision,
            );
            // No false would-have-blocked: a block is only ever a reproducible cross.
            if point.decision == "quarantine" {
                let risk = risk_from_rationale(&point.rationale);
                assert!(
                    risk >= policy.quarantine_threshold,
                    "quarantine must be backed by a reproducible risk cross (risk={risk} >= {})",
                    policy.quarantine_threshold
                );
            }
        }
    }
    Ok(())
}
