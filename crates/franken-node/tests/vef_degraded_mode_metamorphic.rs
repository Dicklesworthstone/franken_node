mod capacity_defaults {
    pub mod aliases {
        pub const MAX_AUDIT_LOG_ENTRIES: usize = 4_096;
    }
}

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

#[path = "../src/security/vef_degraded_mode.rs"]
mod vef_degraded_mode;

use vef_degraded_mode::{
    ActionRisk, ProofLagMetrics, VefActionDecision, VefDegradedModeConfig, VefDegradedModeEngine,
    VefDegradedModeEvent, VefMode,
};

fn default_engine() -> VefDegradedModeEngine {
    VefDegradedModeEngine::new(VefDegradedModeConfig::default())
}

fn restricted_metrics() -> ProofLagMetrics {
    ProofLagMetrics {
        proof_lag_secs: 300,
        backlog_depth: 0,
        error_rate: 0.0,
        heartbeat_age_secs: 0,
    }
}

fn transition_edges(engine: &VefDegradedModeEngine) -> Vec<(VefMode, VefMode)> {
    engine
        .audit_log()
        .iter()
        .filter_map(|event| match event {
            VefDegradedModeEvent::ModeTransition(transition) => {
                Some((transition.current_mode, transition.target_mode))
            }
            _ => None,
        })
        .collect()
}

fn restricted_to_normal_recovery_receipt_count(engine: &VefDegradedModeEngine) -> usize {
    engine
        .audit_log()
        .iter()
        .filter(|event| {
            matches!(
                event,
                VefDegradedModeEvent::RecoveryComplete(receipt)
                    if receipt.from_mode == VefMode::Restricted
                        && receipt.to_mode == VefMode::Normal
            )
        })
        .count()
}

#[test]
fn recovery_window_nonrecovering_insertion_preserves_degraded_commit_metamorphic() {
    let restricted = restricted_metrics();
    let healthy = ProofLagMetrics::healthy();

    let mut baseline = default_engine();
    baseline.observe_metrics(&restricted, 1000, "corr-vef-mr-baseline");
    baseline.observe_metrics(&healthy, 1050, "corr-vef-mr-baseline");
    baseline.observe_metrics(&healthy, 1170, "corr-vef-mr-baseline");
    assert_eq!(baseline.mode(), VefMode::Normal);
    assert_eq!(restricted_to_normal_recovery_receipt_count(&baseline), 1);

    let mut mutated = default_engine();
    mutated.observe_metrics(&restricted, 1000, "corr-vef-mr-mutated");
    mutated.observe_metrics(&healthy, 1050, "corr-vef-mr-mutated");
    mutated.observe_metrics(&restricted, 1100, "corr-vef-mr-mutated");

    let mode_after_insertion = mutated.mode();
    let transitions_after_insertion = transition_edges(&mutated);

    mutated.observe_metrics(&healthy, 1170, "corr-vef-mr-mutated");

    assert_eq!(mode_after_insertion, VefMode::Restricted);
    assert_eq!(mutated.mode(), VefMode::Restricted);
    assert_eq!(transition_edges(&mutated), transitions_after_insertion);
    assert_eq!(restricted_to_normal_recovery_receipt_count(&mutated), 0);
}

#[test]
fn action_policy_and_event_code_contract_metamorphic() {
    let restricted = restricted_metrics();
    let config = VefDegradedModeConfig::default();
    assert_eq!(
        config.restricted_slo.first_breached_metric(&restricted),
        Some("proof_lag_secs")
    );

    let quarantine = ProofLagMetrics {
        proof_lag_secs: 0,
        backlog_depth: config.quarantine_slo.max_backlog_depth,
        error_rate: 0.0,
        heartbeat_age_secs: 0,
    };

    let mut engine = VefDegradedModeEngine::new(config);
    engine.observe_metrics(&quarantine, 2000, "corr-vef-action-policy");
    assert_eq!(engine.mode(), VefMode::Quarantine);
    assert!(
        engine
            .audit_log()
            .iter()
            .any(|event| event.code() == "VEF-DEGRADE-001")
    );

    let blocked: VefActionDecision = engine.evaluate_action(ActionRisk::HighRisk, "publish");
    assert!(!blocked.permitted);
    assert_eq!(blocked.mode, VefMode::Quarantine);

    let warned = engine.evaluate_action(ActionRisk::LowRisk, "inspect");
    assert!(warned.permitted);
    assert_eq!(warned.mode, VefMode::Quarantine);

    let health_check = engine.evaluate_action(ActionRisk::HealthCheck, "probe");
    assert!(health_check.permitted);
    assert_eq!(health_check.mode, VefMode::Quarantine);
}

// bd-8m3oc: this file used to carry a hand-rolled `fn main()` that called the two
// metamorphic checks directly, and Cargo.toml registered it BOTH as a
// `[[bin]] vef-degraded-mode-metamorphic` (no required-features) and as a
// `[[test]] vef_degraded_mode_metamorphic` (required-features =
// ["advanced-features"]) over the same path — which cargo warned about on every
// build of the workspace.
//
// The warning was the smaller half of the problem. Neither registration ran the
// two METAMORPHIC checks this file exists for: they carried no `#[test]`
// attribute, so under the `[[test]]` target libtest's generated main never
// called them and `fn main` sat dead, and nothing ever executed the `[[bin]]`.
// (The 65 inline tests inside the `#[path]`-included `vef_degraded_mode` module
// below did run, which is why the gap was easy to miss — the target reported a
// healthy test count that contained none of this file's own assertions.)
// Marking both checks `#[test]` and dropping the duplicate `[[bin]]`
// registration removes the warning and takes the target from 65 to 67.
