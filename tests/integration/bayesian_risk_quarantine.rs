//! Integration fixture checks for bd-274s:
//! deterministic Bayesian risk updates and reproducible quarantine actions.

use ed25519_dalek::SigningKey;
use frankenengine_node::observability::evidence_ledger::{
    DecisionKind, EvidenceEntry, EvidenceLedger, LedgerCapacity, sign_evidence_entry,
};
use frankenengine_node::policy::bayesian_diagnostics::{
    CandidateRef, E_PROCESS_SCALE_PPM, FN_SENTINEL_E_PROCESS_UPDATED,
    FN_SENTINEL_GUARDRAIL_PRECEDENCE, FN_SENTINEL_HARDENING_MONOTONIC,
    FN_SENTINEL_LEDGER_RECEIPT_APPENDED, FN_SENTINEL_OBSERVATION_INGESTED,
    FN_SENTINEL_REPLAY_VERIFIED, LikelihoodRatioEvidence, RankedCandidate, RuntimeSentinelEProcess,
};
use frankenengine_node::policy::decision_engine::{DecisionEngine, DecisionReason};
use frankenengine_node::policy::guardrail_monitor::{GuardrailMonitorSet, SystemState};
use frankenengine_node::policy::hardening_state_machine::{
    GovernanceRollbackArtifact, HardeningLevel, HardeningStateMachine,
};
use frankenengine_node::policy::runtime_sentinel::{
    FN_SENTINEL_ESCALATION_RECEIPT_SIGNED, FN_SENTINEL_EXPECTED_LOSS_SELECTED,
    RuntimeSentinelObservation, SentinelActionLoss, SentinelContainmentAction,
    SentinelCounterfactualReceipt, SentinelDecisionInput, SentinelExpectedLossPolicy,
    SentinelObservationLog, SentinelSignal, SentinelSignalKind,
};
use frankenengine_node::security::adversary_graph::AdversaryPosterior;
use frankenengine_node::security::quarantine_controller::{
    ControlAction, DEFAULT_QUARANTINE_SCOPE, QuarantineController, QuarantineControllerError,
    QuarantineThresholdPolicy,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fs;

const VALID_EVIDENCE_HASH: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const FIXTURE_REL: &str = "artifacts/10.17/adversary_graph_state.json";

#[derive(Debug, Deserialize)]
struct FixtureState {
    schema_version: String,
    generated_at: String,
    thresholds: Thresholds,
    posteriors: Vec<PosteriorEntry>,
    actions: Vec<ActionEntry>,
}

#[derive(Debug, Deserialize)]
struct Thresholds {
    throttle: f64,
    isolate: f64,
    quarantine: f64,
    revoke: f64,
}

#[derive(Debug, Clone, Deserialize)]
struct PosteriorEntry {
    principal_id: String,
    alpha: u64,
    beta: u64,
    posterior: f64,
    evidence_count: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct ActionEntry {
    principal_id: String,
    decision: String,
    posterior: f64,
    trace_id: String,
    evidence_signature: String,
}

fn fixture_path() -> std::path::PathBuf {
    // Resolve relative to CARGO_MANIFEST_DIR to work reliably regardless of
    // the test runner's CWD (local builds vs remote rch workers).
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut root = manifest.to_path_buf();
    loop {
        let candidate = root.join(FIXTURE_REL);
        if candidate.exists() {
            return candidate;
        }
        if !root.pop() {
            break;
        }
    }
    std::path::PathBuf::from(FIXTURE_REL)
}

fn load_fixture() -> FixtureState {
    let path = fixture_path();
    let raw = fs::read_to_string(&path).expect("failed reading bayesian risk fixture");
    serde_json::from_str::<FixtureState>(&raw)
        .expect("failed parsing bayesian risk fixture as json")
}

fn posterior_from_beta(alpha: u64, beta: u64) -> f64 {
    let total = alpha + beta;
    if total == 0 {
        return 0.0;
    }
    (alpha as f64) / (total as f64)
}

fn deterministic_bayes_update(
    prior_alpha: u64,
    prior_beta: u64,
    observed_successes: u64,
    observed_failures: u64,
) -> f64 {
    posterior_from_beta(
        prior_alpha.saturating_add(observed_successes),
        prior_beta.saturating_add(observed_failures),
    )
}

fn action_for_posterior(posterior: f64, thresholds: &Thresholds) -> Option<&'static str> {
    if posterior >= thresholds.revoke {
        Some("revoke")
    } else if posterior >= thresholds.quarantine {
        Some("quarantine")
    } else if posterior >= thresholds.isolate {
        Some("isolate")
    } else if posterior >= thresholds.throttle {
        Some("throttle")
    } else {
        None
    }
}

fn signed_evidence(principal_id: &str, decision: &str, posterior: f64, trace_id: &str) -> String {
    let payload = format!("{principal_id}|{decision}|{posterior:.12}|{trace_id}");
    let digest = Sha256::digest(payload.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}

fn controller() -> QuarantineController {
    QuarantineController::new(QuarantineThresholdPolicy::default(), "risk-quarantine-key")
        .expect("controller")
}

fn valid_hash(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sentinel_signal(
    kind: SentinelSignalKind,
    source: &str,
    magnitude_bp: u16,
    detail: &str,
) -> SentinelSignal {
    SentinelSignal::new(kind, source, magnitude_bp, detail).expect("valid sentinel signal")
}

fn sentinel_evidence(
    sequence: u64,
    signal_id: &str,
    likelihood_ratio_ppm: u64,
) -> LikelihoodRatioEvidence {
    LikelihoodRatioEvidence::new(signal_id, sequence, likelihood_ratio_ppm)
}

fn sentinel_candidate(id: &str, posterior_prob: f64, guardrail_filtered: bool) -> RankedCandidate {
    RankedCandidate {
        candidate_ref: CandidateRef::new(id),
        posterior_prob,
        prior_prob: 0.5,
        observation_count: 32,
        confidence_interval: (posterior_prob - 0.01, posterior_prob + 0.01),
        guardrail_filtered,
    }
}

fn sentinel_system_state() -> SystemState {
    SystemState {
        memory_used_bytes: 256_000_000,
        memory_budget_bytes: 1_000_000_000,
        durability_level: 0.99,
        hardening_level: HardeningLevel::Standard,
        proposed_hardening_level: None,
        evidence_emission_active: true,
        memory_tail_risk: None,
        reliability_telemetry: None,
        epoch_id: 91,
    }
}

fn sentinel_governance_artifact() -> GovernanceRollbackArtifact {
    GovernanceRollbackArtifact {
        artifact_id: "GOV-SENTINEL-2026-001".to_string(),
        approver_id: "policy-board@franken.node".to_string(),
        reason: "Bounded operator rollback after signed escalation review".to_string(),
        timestamp: 91_500,
        signature: "sig:sentinel-governance-rollback".to_string(),
    }
}

fn signed_sentinel_ledger_entry(
    decision_id: &str,
    trace_id: &str,
    payload: Value,
    key: &SigningKey,
) -> EvidenceEntry {
    let mut entry = EvidenceEntry {
        schema_version: "runtime-sentinel-decision-v1".to_string(),
        entry_id: None,
        decision_id: decision_id.to_string(),
        decision_kind: DecisionKind::Quarantine,
        decision_time: "2026-06-15T20:10:00Z".to_string(),
        timestamp_ms: 91_000,
        trace_id: trace_id.to_string(),
        epoch_id: 91,
        payload,
        size_bytes: 0,
        signature: String::new(),
        prev_entry_hash: String::new(),
    };
    sign_evidence_entry(&mut entry, key);
    entry
}

fn transcript_codes(transcript: &[Value]) -> Vec<&str> {
    transcript
        .iter()
        .map(|event| {
            event
                .get("event_code")
                .and_then(Value::as_str)
                .expect("event code")
        })
        .collect()
}

fn sentinel_decision_input(posterior_malice_bp: u16) -> SentinelDecisionInput {
    SentinelDecisionInput::new(
        "npm:@acme/risky-sentinel",
        "trace-sentinel-91",
        91,
        posterior_malice_bp,
        20_000_000,
        50_000,
        3,
        VALID_EVIDENCE_HASH,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
}

fn low_risk_argmin_policy(floor: SentinelContainmentAction) -> SentinelExpectedLossPolicy {
    SentinelExpectedLossPolicy::new(
        vec![
            SentinelActionLoss::new(SentinelContainmentAction::Allow, 0, 2_000),
            SentinelActionLoss::new(SentinelContainmentAction::Harden, 700, 2_500),
            SentinelActionLoss::new(SentinelContainmentAction::SafeMode, 3_000, 1_500),
            SentinelActionLoss::new(SentinelContainmentAction::Quarantine, 8_000, 200),
        ],
        floor,
    )
    .expect("valid low-risk policy")
}

#[test]
fn sentinel_transcript_replays_eprocess_and_ledgers_signed_escalation() {
    let mut observation =
        RuntimeSentinelObservation::new("npm:@acme/risky-sentinel", 91, 1, "2026-06-15T20:10:00Z");
    observation
        .push_signal(sentinel_signal(
            SentinelSignalKind::PolicyViolation,
            "guardrail:ambient-authority",
            10_000,
            "ambient authority denied",
        ))
        .expect("push policy signal");
    observation
        .push_signal(sentinel_signal(
            SentinelSignalKind::CamouflageHint,
            "trajectory:gaming",
            8_750,
            "GradualCreep",
        ))
        .expect("push camouflage signal");

    let mut observation_log = SentinelObservationLog::new();
    observation_log
        .ingest(observation)
        .expect("observation is canonical");
    let observation_digest = observation_log.digest().expect("log digest");

    let evidence = [
        sentinel_evidence(1, "policy_violation", E_PROCESS_SCALE_PPM * 2),
        sentinel_evidence(2, "camouflage_hint", E_PROCESS_SCALE_PPM * 5),
        sentinel_evidence(3, "effect_receipt_anomaly", E_PROCESS_SCALE_PPM * 2),
    ];

    let mut live_process = RuntimeSentinelEProcess::new();
    let updates: Vec<_> = evidence
        .iter()
        .map(|item| live_process.observe(item).expect("e-process update"))
        .collect();
    let replayed_process =
        RuntimeSentinelEProcess::replay_from(&evidence).expect("verifier replay");

    assert_eq!(
        live_process, replayed_process,
        "verifier recomputation must recover the exact fixed-point e-process state"
    );
    assert!(
        live_process.should_escalate(50_000),
        "20x e-value should cross the alpha=0.05 escalation boundary"
    );
    assert_eq!(live_process.false_alarm_bound_ppm(), 50_000);

    let candidates = [
        sentinel_candidate("terminate-extension", 0.999, true),
        sentinel_candidate("quarantine-extension", 0.001, false),
    ];
    let outcome = DecisionEngine::new(91).decide(
        &candidates,
        &GuardrailMonitorSet::new(),
        &sentinel_system_state(),
    );

    assert_eq!(
        outcome.reason,
        DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank: 1 }
    );
    assert_eq!(
        outcome.chosen,
        Some(CandidateRef::new("quarantine-extension"))
    );
    assert_eq!(
        outcome
            .blocked
            .first()
            .expect("guardrail-filtered candidate is recorded")
            .candidate,
        CandidateRef::new("terminate-extension")
    );

    let mut hardening = HardeningStateMachine::with_level(HardeningLevel::Standard);
    let escalation = hardening
        .escalate(HardeningLevel::Enhanced, 91_100, "trace-sentinel-91")
        .expect("sentinel escalation hardens");
    let regression = hardening.escalate(HardeningLevel::Baseline, 91_200, "trace-sentinel-91");
    assert!(
        regression.is_err(),
        "plain downshift must be rejected after escalation"
    );
    let rollback = hardening
        .governance_rollback(
            HardeningLevel::Standard,
            &sentinel_governance_artifact(),
            91_300,
            "trace-sentinel-91",
        )
        .expect("signed governance rollback");
    assert_eq!(escalation.to_level, HardeningLevel::Enhanced);
    assert_eq!(rollback.to_level, HardeningLevel::Standard);

    let transcript = vec![
        json!({
            "event_code": FN_SENTINEL_OBSERVATION_INGESTED,
            "observation_log_digest": observation_digest,
        }),
        json!({
            "event_code": FN_SENTINEL_E_PROCESS_UPDATED,
            "updates": updates,
            "evidence_count": live_process.evidence_count,
            "e_value_ppm": live_process.e_value_ppm,
            "false_alarm_bound_ppm": live_process.false_alarm_bound_ppm(),
        }),
        json!({
            "event_code": FN_SENTINEL_GUARDRAIL_PRECEDENCE,
            "chosen": outcome.chosen,
            "blocked": outcome.blocked,
            "reason": outcome.reason,
        }),
        json!({
            "event_code": FN_SENTINEL_HARDENING_MONOTONIC,
            "transition_count": hardening.transition_count(),
            "current_level": hardening.current_level().label(),
        }),
        json!({
            "event_code": FN_SENTINEL_REPLAY_VERIFIED,
            "replayed_e_value_ppm": replayed_process.e_value_ppm,
            "replayed_evidence_count": replayed_process.evidence_count,
        }),
    ];
    assert_eq!(
        transcript_codes(&transcript),
        vec![
            FN_SENTINEL_OBSERVATION_INGESTED,
            FN_SENTINEL_E_PROCESS_UPDATED,
            FN_SENTINEL_GUARDRAIL_PRECEDENCE,
            FN_SENTINEL_HARDENING_MONOTONIC,
            FN_SENTINEL_REPLAY_VERIFIED,
        ],
        "inline golden transcript must keep stable FN-SENTINEL event order"
    );

    let key = SigningKey::from_bytes(&[0x5E; 32]);
    let mut ledger =
        EvidenceLedger::with_verifying_key(LedgerCapacity::new(4, 16_384), key.verifying_key());
    let ledger_entry = signed_sentinel_ledger_entry(
        "sentinel-quarantine-npm-acme-risky",
        "trace-sentinel-91",
        json!({
            "event_code": FN_SENTINEL_LEDGER_RECEIPT_APPENDED,
            "transcript": transcript,
            "decision": "quarantine-extension",
            "rollback_command": "franken-node trust release npm:@acme/risky-sentinel --trace trace-sentinel-91",
        }),
        &key,
    );
    let entry_id = ledger
        .append(ledger_entry)
        .expect("signed sentinel evidence appends");

    assert_eq!(entry_id.0, 1);
    assert_eq!(ledger.len(), 1);
    let stored = ledger.iter_all().next().expect("stored ledger entry");
    assert_eq!(stored.1.decision_kind, DecisionKind::Quarantine);
    assert_eq!(
        stored.1.payload["event_code"],
        json!(FN_SENTINEL_LEDGER_RECEIPT_APPENDED)
    );
    assert!(
        stored.1.payload["rollback_command"]
            .as_str()
            .expect("rollback command")
            .contains("trust release"),
        "signed ledger payload must retain an operator rollback command"
    );
}

#[test]
fn sentinel_expected_loss_policy_selects_argmin_and_respects_guardrail_floor() {
    let policy = low_risk_argmin_policy(SentinelContainmentAction::SafeMode);
    let decision = policy
        .decide(sentinel_decision_input(1_500), None)
        .expect("expected-loss decision");

    assert_eq!(decision.event_code, FN_SENTINEL_EXPECTED_LOSS_SELECTED);
    assert_eq!(
        decision.raw_selected_action,
        SentinelContainmentAction::Allow
    );
    assert_eq!(
        decision.selected_action,
        SentinelContainmentAction::SafeMode
    );
    assert!(decision.guardrail_applied);
    assert_eq!(
        decision.selected_action.hardening_floor(),
        Some(HardeningLevel::Maximum)
    );
    assert!(decision.selected_action.requires_safe_mode());
    assert_eq!(
        decision.selected_action.quarantine_control_action(),
        Some(ControlAction::Isolate)
    );
    assert_eq!(decision.confidence_bp, 9_500);
    assert!(
        decision.rationale.contains("e_value_ppm=20000000"),
        "receipt rationale must bind the anytime-valid e-value"
    );
    assert!(
        decision.rationale.contains("posterior_malice_bp=1500"),
        "receipt rationale must bind the posterior"
    );
}

#[test]
fn sentinel_expected_loss_receipt_signs_ledger_payload_with_counterfactual_threshold() {
    let counterfactual = SentinelCounterfactualReceipt::threshold_crossing(
        "obs:policy_violation:seq3",
        SentinelContainmentAction::SafeMode,
        SentinelContainmentAction::Quarantine,
        4_000_000,
        20_000_000,
        SentinelContainmentAction::Quarantine,
    );
    let decision = SentinelExpectedLossPolicy::default()
        .decide(sentinel_decision_input(8_200), Some(counterfactual))
        .expect("default policy decision");

    assert_eq!(
        decision.selected_action,
        SentinelContainmentAction::Quarantine
    );
    assert!(!decision.guardrail_applied);
    let receipt_counterfactual = decision
        .counterfactual
        .as_ref()
        .expect("counterfactual threshold receipt");
    assert_eq!(
        receipt_counterfactual.observation_ref,
        "obs:policy_violation:seq3"
    );
    assert!(
        receipt_counterfactual
            .rationale
            .contains("moved action from safe_mode to quarantine")
    );

    let key = SigningKey::from_bytes(&[0xC7; 32]);
    let entry = decision
        .to_signed_evidence_entry("2026-06-15T20:11:00Z", 91_100, &key)
        .expect("signed receipt entry");

    assert_eq!(entry.decision_kind, DecisionKind::Quarantine);
    assert_eq!(entry.schema_version, "runtime_sentinel.decision.v1");
    assert_eq!(
        entry.payload["event_code"],
        json!(FN_SENTINEL_ESCALATION_RECEIPT_SIGNED)
    );
    assert_eq!(
        entry.payload["decision"]["event_code"],
        json!(FN_SENTINEL_EXPECTED_LOSS_SELECTED)
    );
    assert_eq!(
        entry.payload["decision"]["selected_action"],
        json!("quarantine")
    );
    assert_eq!(
        entry.payload["decision"]["counterfactual"]["observation_ref"],
        json!("obs:policy_violation:seq3")
    );

    let mut ledger =
        EvidenceLedger::with_verifying_key(LedgerCapacity::new(2, 16_384), key.verifying_key());
    let entry_id = ledger.append(entry).expect("signed receipt appends");
    assert_eq!(entry_id.0, 1);
    assert_eq!(ledger.len(), 1);
}

#[test]
fn sentinel_quarantine_action_actuates_existing_hardening_and_quarantine_surfaces() {
    let decision = SentinelExpectedLossPolicy::default()
        .decide(sentinel_decision_input(8_200), None)
        .expect("default policy decision");
    assert_eq!(
        decision.selected_action,
        SentinelContainmentAction::Quarantine
    );

    let mut hardening = HardeningStateMachine::with_level(HardeningLevel::Standard);
    assert_eq!(
        decision.selected_action.hardening_floor(),
        Some(HardeningLevel::Critical)
    );
    let transition = hardening
        .escalate(HardeningLevel::Critical, 91_200, &decision.trace_id)
        .expect("quarantine action hardens to critical");
    assert_eq!(transition.to_level, HardeningLevel::Critical);
    assert_eq!(hardening.current_level(), HardeningLevel::Critical);

    let controller = controller();
    let control = controller
        .decide_for_posterior_with_context(
            &decision.principal_id,
            f64::from(decision.posterior_malice_bp) / 10_000.0,
            decision.evidence_count,
            &decision.evidence_hash,
            DEFAULT_QUARANTINE_SCOPE,
            &decision.trace_id,
        )
        .expect("valid quarantine evidence context")
        .expect("posterior should require quarantine control");

    assert_eq!(control.action, ControlAction::Quarantine);
    assert!(controller.verify_decision(&control));
}

#[test]
fn sentinel_benign_streams_respect_anytime_false_alarm_bound() {
    const ALPHA_PPM: u64 = 50_000;
    const BENIGN_STREAMS: u64 = 64;

    let mut false_alarm_streams = 0_u64;
    for stream_id in 0..BENIGN_STREAMS {
        let mut process = RuntimeSentinelEProcess::new();
        let mut ever_escalated = false;

        for step in 1..=32_u64 {
            let likelihood_ratio_ppm = if (stream_id + step) % 2 == 0 {
                1_100_000
            } else {
                900_000
            };
            let evidence = sentinel_evidence(step, "benign_control", likelihood_ratio_ppm);
            process
                .observe(&evidence)
                .expect("benign evidence sequence is monotonic");
            ever_escalated |= process.should_escalate(ALPHA_PPM);
        }

        if ever_escalated {
            false_alarm_streams = false_alarm_streams.saturating_add(1);
        }
    }

    let allowed_false_alarms =
        (BENIGN_STREAMS.saturating_mul(ALPHA_PPM)).div_ceil(E_PROCESS_SCALE_PPM);
    assert!(
        false_alarm_streams <= allowed_false_alarms,
        "continuous peeking false alarms {false_alarm_streams} exceeded Ville bound allowance {allowed_false_alarms}"
    );

    let planted_malicious = [
        sentinel_evidence(1, "planted_malice", 2_500_000),
        sentinel_evidence(2, "planted_malice", 2_500_000),
        sentinel_evidence(3, "planted_malice", 2_500_000),
        sentinel_evidence(4, "planted_malice", 2_500_000),
    ];
    let planted_process =
        RuntimeSentinelEProcess::replay_from(&planted_malicious).expect("planted replay");

    assert!(
        planted_process.should_escalate(ALPHA_PPM),
        "planted malicious stream must cross the same anytime-valid boundary"
    );
    assert_eq!(
        planted_process.false_alarm_bound_ppm(),
        25_600,
        "2.5^4 e-value should produce the expected fixed-point Ville bound"
    );
}

#[test]
fn deterministic_posterior_updates_match_identical_inputs() {
    let a = deterministic_bayes_update(3, 4, 7, 2);
    let b = deterministic_bayes_update(3, 4, 7, 2);
    assert!(
        (a - b).abs() < 1e-12,
        "deterministic Bayesian update must be stable for identical evidence"
    );
    assert!(
        (a - (10.0 / 16.0)).abs() < 1e-12,
        "posterior should match the expected closed-form value"
    );
}

#[test]
fn threshold_policy_maps_to_all_control_actions() {
    let fixture = load_fixture();
    let thresholds = fixture.thresholds;

    let cases = [
        (0.46_f64, "throttle"),
        (0.61_f64, "isolate"),
        (0.80_f64, "quarantine"),
        (0.95_f64, "revoke"),
    ];

    for (posterior, expected) in cases {
        let actual =
            action_for_posterior(posterior, &thresholds).expect("expected threshold action");
        assert_eq!(
            actual, expected,
            "threshold policy should deterministically map posterior to action"
        );
    }
}

#[test]
fn fixture_posteriors_align_with_beta_parameters() {
    let fixture = load_fixture();
    assert_eq!(fixture.schema_version, "adversary-graph-state-v1");
    assert!(
        fixture.generated_at.ends_with('Z'),
        "fixture timestamp should be UTC RFC3339"
    );

    for row in fixture.posteriors {
        let expected = posterior_from_beta(row.alpha, row.beta);
        assert!(
            (expected - row.posterior).abs() < 1e-12,
            "posterior mismatch for {}: expected {expected}, got {}",
            row.principal_id,
            row.posterior
        );
        assert!(
            row.evidence_count > 0,
            "evidence_count must be non-zero for {}",
            row.principal_id
        );
    }
}

#[test]
fn fixture_actions_have_deterministic_signatures() {
    let fixture = load_fixture();
    let thresholds = fixture.thresholds;

    for action in fixture.actions {
        let expected_decision = action_for_posterior(action.posterior, &thresholds)
            .expect("missing threshold decision");
        assert_eq!(
            action.decision, expected_decision,
            "decision mismatch for {}",
            action.principal_id
        );

        let expected_signature = signed_evidence(
            &action.principal_id,
            &action.decision,
            action.posterior,
            &action.trace_id,
        );
        assert_eq!(
            action.evidence_signature, expected_signature,
            "signed evidence mismatch for {}",
            action.principal_id
        );
    }
}

#[test]
fn quarantine_controller_rejects_placeholder_evidence_context_before_signing() {
    let err = controller()
        .decide_for_posterior_with_context(
            "ext:sentinel",
            0.91,
            0,
            "sha256:untracked",
            DEFAULT_QUARANTINE_SCOPE,
            "trace-sentinel",
        )
        .expect_err("placeholder evidence context must fail closed");

    assert!(matches!(
        err,
        QuarantineControllerError::InvalidEvidenceContext {
            evidence_count: 0,
            ..
        }
    ));
}

#[test]
fn quarantine_controller_convenience_path_rejects_missing_context() {
    let controller = controller();

    let err = controller
        .decide_for_posterior("ext:context", 0.91, "trace-context")
        .expect_err("actionable posterior without evidence context must fail closed");
    assert!(matches!(
        err,
        QuarantineControllerError::InvalidEvidenceContext {
            evidence_count: 0,
            evidence_hash_len: 0
        }
    ));
}

#[test]
fn quarantine_controller_context_path_uses_valid_hash_and_verifies() {
    let controller = controller();
    let decision = controller
        .decide_for_posterior_with_context(
            "ext:context",
            0.91,
            1,
            VALID_EVIDENCE_HASH,
            DEFAULT_QUARANTINE_SCOPE,
            "trace-context",
        )
        .expect("valid evidence context")
        .expect("actionable posterior should produce a decision");

    assert_eq!(decision.action, ControlAction::Revoke);
    assert_eq!(decision.evidence_count, 1);
    assert!(valid_hash(&decision.evidence_hash));
    assert_ne!(decision.evidence_hash, "sha256:untracked");
    assert!(controller.verify_decision(&decision));
}

#[test]
fn quarantine_controller_evaluate_rejects_invalid_evidence_hash() {
    let posterior = AdversaryPosterior {
        principal_id: "ext:invalid-evidence".to_string(),
        alpha: 1,
        beta: 1,
        posterior: 0.91,
        evidence_count: 1,
        last_trace_id: "trace-invalid-evidence".to_string(),
        evidence_hash: "sha256:untracked".to_string(),
    };

    let err = controller()
        .evaluate(&posterior)
        .expect_err("invalid evidence hash must fail closed");
    assert!(matches!(
        err,
        QuarantineControllerError::InvalidEvidenceContext {
            evidence_count: 1,
            ..
        }
    ));
}

#[test]
fn fixture_actions_are_sorted_for_replay_determinism() {
    let fixture = load_fixture();
    let mut sorted = fixture.actions.clone();

    sorted.sort_by(|left, right| {
        right
            .posterior
            .partial_cmp(&left.posterior)
            .unwrap_or(Ordering::Equal)
            .then_with(|| left.principal_id.cmp(&right.principal_id))
    });

    assert_eq!(
        fixture.actions.len(),
        sorted.len(),
        "fixture action count mismatch"
    );
    for (idx, expected) in sorted.iter().enumerate() {
        let actual = &fixture.actions[idx];
        assert_eq!(
            (
                actual.principal_id.as_str(),
                actual.decision.as_str(),
                actual.posterior
            ),
            (
                expected.principal_id.as_str(),
                expected.decision.as_str(),
                expected.posterior
            ),
            "action at index {idx} must match deterministic sort order for replay traces"
        );
    }
}
