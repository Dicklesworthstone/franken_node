use frankenengine_node::security::vef_degraded_mode::{
    ProofLagMetrics, VefDegradedModeConfig, VefDegradedModeEngine, VefDegradedModeEvent, VefMode,
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

fn main() {
    recovery_window_nonrecovering_insertion_preserves_degraded_commit_metamorphic();
}
