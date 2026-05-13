#[path = "../src/hostcall_s3_fifo.rs"]
mod hostcall_s3_fifo;

use hostcall_s3_fifo::{
    S3FifoConfig, S3FifoDecisionKind, S3FifoFallbackReason, S3FifoPolicy, S3FifoTier,
};

#[test]
fn smoke_policy_admits_then_promotes() {
    let mut policy = S3FifoPolicy::new(S3FifoConfig::default());
    let _cfg = policy.config();
    let first = policy.access("ext-smoke", "key-smoke".to_string());
    let second = policy.access("ext-smoke", "key-smoke".to_string());

    assert_eq!(first.kind, S3FifoDecisionKind::AdmitSmall);
    assert_eq!(second.kind, S3FifoDecisionKind::PromoteSmallToMain);
}

#[test]
fn fallback_clear_recovers_from_bypass_mode() {
    let mut policy = S3FifoPolicy::new(S3FifoConfig {
        live_capacity: 4,
        small_capacity: 2,
        ghost_capacity: 4,
        max_entries_per_owner: 4,
        fallback_window: 3,
        min_ghost_hits_in_window: 3,
        max_budget_rejections_in_window: 3,
    });

    for idx in 0..3 {
        let _ = policy.access("ext-a", format!("cold-{idx}"));
    }

    assert!(
        policy.telemetry().fallback_reason.is_some(),
        "fallback should trigger after low-signal window"
    );

    let bypass = policy.access("ext-a", "while-fallback".to_string());
    assert_eq!(bypass.kind, S3FifoDecisionKind::FallbackBypass);

    policy.clear_fallback();
    let resumed = policy.access("ext-a", "after-clear".to_string());
    assert_ne!(resumed.kind, S3FifoDecisionKind::FallbackBypass);
}

#[test]
fn owner_budget_rejects_third_unique_live_key() {
    let mut policy = S3FifoPolicy::new(S3FifoConfig {
        live_capacity: 8,
        small_capacity: 4,
        ghost_capacity: 8,
        max_entries_per_owner: 2,
        fallback_window: 32,
        min_ghost_hits_in_window: 0,
        max_budget_rejections_in_window: 32,
    });

    let d1 = policy.access("ext-budget", "k1".to_string());
    let d2 = policy.access("ext-budget", "k2".to_string());
    let d3 = policy.access("ext-budget", "k3".to_string());

    assert_eq!(d1.kind, S3FifoDecisionKind::AdmitSmall);
    assert_eq!(d2.kind, S3FifoDecisionKind::AdmitSmall);
    assert_eq!(d3.kind, S3FifoDecisionKind::RejectFairnessBudget);
    assert_eq!(policy.telemetry().budget_rejections_total, 1);
}

#[test]
fn ghost_hit_reentry_admits_from_ghost() {
    let mut policy = S3FifoPolicy::new(S3FifoConfig {
        live_capacity: 4,
        small_capacity: 1,
        ghost_capacity: 4,
        max_entries_per_owner: 4,
        fallback_window: 8,
        min_ghost_hits_in_window: 0,
        max_budget_rejections_in_window: 8,
    });

    let first = policy.access("ext-a", "k1".to_string());
    assert_eq!(first.kind, S3FifoDecisionKind::AdmitSmall);

    let _ = policy.access("ext-b", "k2".to_string());
    let reentry = policy.access("ext-a", "k1".to_string());

    assert_eq!(reentry.kind, S3FifoDecisionKind::AdmitFromGhost);
    assert!(reentry.ghost_hit, "reentry should come from ghost history");
    assert!(
        policy.telemetry().ghost_hits_total >= 1,
        "ghost hit counter should increment on reentry"
    );
}

#[test]
fn ghost_hit_budget_rejection_uses_ghost_tier_and_counts_both_signals() {
    let mut policy = S3FifoPolicy::new(S3FifoConfig {
        live_capacity: 3,
        small_capacity: 1,
        ghost_capacity: 4,
        max_entries_per_owner: 1,
        fallback_window: 32,
        min_ghost_hits_in_window: 0,
        max_budget_rejections_in_window: 32,
    });

    let seed = policy.access("ext-a", "k1".to_string());
    assert_eq!(seed.kind, S3FifoDecisionKind::AdmitSmall);

    let _ = policy.access("ext-b", "k2".to_string());
    let budget_holder = policy.access("ext-a", "k3".to_string());
    assert_eq!(budget_holder.kind, S3FifoDecisionKind::AdmitSmall);

    let ghost_reject = policy.access("ext-a", "k1".to_string());
    assert_eq!(ghost_reject.kind, S3FifoDecisionKind::RejectFairnessBudget);
    assert!(ghost_reject.ghost_hit);
    assert_eq!(ghost_reject.tier, S3FifoTier::Ghost);

    let telemetry = policy.telemetry();
    assert_eq!(telemetry.ghost_hits_total, 1);
    assert_eq!(telemetry.budget_rejections_total, 1);
}

#[test]
fn ghost_hit_counter_tracks_repeated_reentries_exactly() {
    let mut policy = S3FifoPolicy::new(S3FifoConfig {
        live_capacity: 2,
        small_capacity: 1,
        ghost_capacity: 4,
        max_entries_per_owner: 4,
        fallback_window: 32,
        min_ghost_hits_in_window: 0,
        max_budget_rejections_in_window: 32,
    });

    let sequence = [
        ("ext-a", "k1"),
        ("ext-a", "k1"),
        ("ext-b", "k2"),
        ("ext-c", "k3"),
        ("ext-b", "k2"),
        ("ext-a", "k1"),
        ("ext-a", "k1"),
    ];

    let mut expected_ghost_hits = 0u64;
    for (owner, key) in sequence {
        let decision = policy.access(owner, key.to_string());
        if decision.ghost_hit {
            expected_ghost_hits = expected_ghost_hits.saturating_add(1);
            assert_eq!(decision.kind, S3FifoDecisionKind::AdmitFromGhost);
            assert_eq!(decision.tier, S3FifoTier::Main);
        }
        assert_eq!(policy.telemetry().ghost_hits_total, expected_ghost_hits);
    }

    assert_eq!(expected_ghost_hits, 2);
}

#[test]
fn telemetry_snapshot_invariants_hold_after_mixed_sequence() {
    let config = S3FifoConfig {
        live_capacity: 6,
        small_capacity: 2,
        ghost_capacity: 8,
        max_entries_per_owner: 3,
        fallback_window: 32,
        min_ghost_hits_in_window: 0,
        max_budget_rejections_in_window: 32,
    };
    let mut policy = S3FifoPolicy::new(config);

    let sequence = [
        ("ext-a", "k1"),
        ("ext-a", "k1"),
        ("ext-b", "k2"),
        ("ext-c", "k3"),
        ("ext-b", "k4"),
        ("ext-a", "k5"),
        ("ext-c", "k3"),
    ];
    for (owner, key) in sequence {
        let _ = policy.access(owner, key.to_string());
    }

    let telemetry = policy.telemetry();
    let owner_sum: usize = telemetry.owner_live_counts.values().copied().sum();

    assert_eq!(
        telemetry.live_depth,
        telemetry.small_depth + telemetry.main_depth
    );
    assert_eq!(owner_sum, telemetry.live_depth);
    assert!(telemetry.live_depth <= config.live_capacity);
    assert!(telemetry.fallback_reason.is_none());
}

#[test]
fn fallback_bypass_emits_conservative_reason_and_tier_markers() {
    let mut policy = S3FifoPolicy::new(S3FifoConfig {
        live_capacity: 4,
        small_capacity: 2,
        ghost_capacity: 4,
        max_entries_per_owner: 4,
        fallback_window: 3,
        min_ghost_hits_in_window: 3,
        max_budget_rejections_in_window: 3,
    });

    for idx in 0..3 {
        let _ = policy.access("ext-a", format!("cold-{idx}"));
    }

    let telemetry_before = policy.telemetry();
    assert_eq!(
        telemetry_before.fallback_reason,
        Some(S3FifoFallbackReason::SignalQualityInsufficient)
    );

    let bypass = policy.access("ext-a", "while-fallback".to_string());
    let telemetry_after = policy.telemetry();
    assert_eq!(bypass.kind, S3FifoDecisionKind::FallbackBypass);
    assert_eq!(bypass.tier, S3FifoTier::Fallback);
    assert_eq!(bypass.fallback_reason, telemetry_after.fallback_reason);
    assert!(!bypass.ghost_hit);
    assert_eq!(telemetry_after.live_depth, telemetry_before.live_depth);
    assert_eq!(telemetry_after.ghost_depth, telemetry_before.ghost_depth);
}

#[test]
fn identical_sequences_yield_identical_decision_and_telemetry_traces() {
    let config = S3FifoConfig {
        live_capacity: 5,
        small_capacity: 2,
        ghost_capacity: 6,
        max_entries_per_owner: 2,
        fallback_window: 8,
        min_ghost_hits_in_window: 0,
        max_budget_rejections_in_window: 8,
    };
    let mut policy_a = S3FifoPolicy::new(config);
    let mut policy_b = S3FifoPolicy::new(config);

    let sequence = [
        ("ext-a", "k1"),
        ("ext-b", "k2"),
        ("ext-a", "k1"),
        ("ext-c", "k3"),
        ("ext-b", "k4"),
        ("ext-a", "k5"),
        ("ext-c", "k3"),
        ("ext-b", "k2"),
    ];

    let mut decisions_a = Vec::new();
    let mut decisions_b = Vec::new();
    let mut telemetry_a = Vec::new();
    let mut telemetry_b = Vec::new();

    for (owner, key) in sequence {
        decisions_a.push(policy_a.access(owner, key.to_string()));
        telemetry_a.push(policy_a.telemetry());
    }
    for (owner, key) in sequence {
        decisions_b.push(policy_b.access(owner, key.to_string()));
        telemetry_b.push(policy_b.telemetry());
    }

    assert_eq!(decisions_a, decisions_b);
    assert_eq!(telemetry_a, telemetry_b);
}

#[test]
fn fallback_fairness_window_uses_strictly_greater_budget_threshold() {
    let mut policy = S3FifoPolicy::new(S3FifoConfig {
        live_capacity: 8,
        small_capacity: 4,
        ghost_capacity: 8,
        max_entries_per_owner: 1,
        fallback_window: 3,
        min_ghost_hits_in_window: 0,
        max_budget_rejections_in_window: 2,
    });

    let d1 = policy.access("ext-a", "k1".to_string());
    let d2 = policy.access("ext-a", "k2".to_string());
    let d3 = policy.access("ext-a", "k3".to_string());

    assert_eq!(d1.kind, S3FifoDecisionKind::AdmitSmall);
    assert_eq!(d2.kind, S3FifoDecisionKind::RejectFairnessBudget);
    assert_eq!(d3.kind, S3FifoDecisionKind::RejectFairnessBudget);
    assert_eq!(
        policy.telemetry().fallback_reason,
        None,
        "fallback must not trigger when rejections equal the configured threshold"
    );

    let d4 = policy.access("ext-a", "k4".to_string());
    assert_eq!(d4.kind, S3FifoDecisionKind::RejectFairnessBudget);
    assert_eq!(
        policy.telemetry().fallback_reason,
        Some(S3FifoFallbackReason::FairnessInstability)
    );

    let d5 = policy.access("ext-a", "k5".to_string());
    assert_eq!(d5.kind, S3FifoDecisionKind::FallbackBypass);
    assert_eq!(d5.tier, S3FifoTier::Fallback);
    assert_eq!(
        d5.fallback_reason,
        Some(S3FifoFallbackReason::FairnessInstability)
    );
}

#[test]
fn fallback_reason_prefers_signal_quality_when_ghost_hits_are_insufficient() {
    let mut policy = S3FifoPolicy::new(S3FifoConfig {
        live_capacity: 8,
        small_capacity: 4,
        ghost_capacity: 8,
        max_entries_per_owner: 1,
        fallback_window: 3,
        min_ghost_hits_in_window: 3,
        max_budget_rejections_in_window: 0,
    });

    let _ = policy.access("ext-a", "k1".to_string());
    let _ = policy.access("ext-a", "k2".to_string());
    let _ = policy.access("ext-a", "k3".to_string());

    assert_eq!(
        policy.telemetry().fallback_reason,
        Some(S3FifoFallbackReason::SignalQualityInsufficient),
        "low ghost-hit signal should take precedence over fairness-instability classification"
    );
}

#[test]
fn clear_fallback_resets_window_and_delays_fairness_retrigger() {
    let mut policy = S3FifoPolicy::new(S3FifoConfig {
        live_capacity: 8,
        small_capacity: 4,
        ghost_capacity: 8,
        max_entries_per_owner: 1,
        fallback_window: 3,
        min_ghost_hits_in_window: 0,
        max_budget_rejections_in_window: 1,
    });

    let _ = policy.access("ext-a", "k1".to_string());
    let _ = policy.access("ext-a", "k2".to_string());
    let _ = policy.access("ext-a", "k3".to_string());
    assert_eq!(
        policy.telemetry().fallback_reason,
        Some(S3FifoFallbackReason::FairnessInstability)
    );

    policy.clear_fallback();
    assert!(policy.telemetry().fallback_reason.is_none());

    let post_clear_1 = policy.access("ext-a", "k4".to_string());
    assert_eq!(post_clear_1.kind, S3FifoDecisionKind::RejectFairnessBudget);
    assert!(
        policy.telemetry().fallback_reason.is_none(),
        "one rejection after clear cannot retrigger before the fallback window refills"
    );

    let post_clear_2 = policy.access("ext-a", "k5".to_string());
    assert_eq!(post_clear_2.kind, S3FifoDecisionKind::RejectFairnessBudget);
    assert!(policy.telemetry().fallback_reason.is_none());

    let post_clear_3 = policy.access("ext-a", "k6".to_string());
    assert_eq!(post_clear_3.kind, S3FifoDecisionKind::RejectFairnessBudget);
    assert_eq!(
        policy.telemetry().fallback_reason,
        Some(S3FifoFallbackReason::FairnessInstability)
    );
}

#[test]
fn clear_fallback_preserves_cumulative_counters_and_future_accumulation() {
    let mut policy = S3FifoPolicy::new(S3FifoConfig {
        live_capacity: 3,
        small_capacity: 1,
        ghost_capacity: 4,
        max_entries_per_owner: 1,
        fallback_window: 4,
        min_ghost_hits_in_window: 0,
        max_budget_rejections_in_window: 1,
    });

    let _ = policy.access("ext-a", "k1".to_string());
    let _ = policy.access("ext-b", "k2".to_string());
    let _ = policy.access("ext-a", "k3".to_string());

    let ghost_reject = policy.access("ext-a", "k1".to_string());
    assert_eq!(ghost_reject.kind, S3FifoDecisionKind::RejectFairnessBudget);
    assert!(ghost_reject.ghost_hit);

    let fallback_trigger = policy.access("ext-a", "k4".to_string());
    assert_eq!(
        fallback_trigger.kind,
        S3FifoDecisionKind::RejectFairnessBudget
    );
    assert_eq!(
        policy.telemetry().fallback_reason,
        Some(S3FifoFallbackReason::FairnessInstability)
    );

    let before_clear = policy.telemetry();
    assert_eq!(before_clear.ghost_hits_total, 1);
    assert_eq!(before_clear.budget_rejections_total, 2);

    let bypass = policy.access("ext-a", "while-fallback".to_string());
    assert_eq!(bypass.kind, S3FifoDecisionKind::FallbackBypass);
    let after_bypass = policy.telemetry();
    assert_eq!(after_bypass.ghost_hits_total, before_clear.ghost_hits_total);
    assert_eq!(
        after_bypass.budget_rejections_total,
        before_clear.budget_rejections_total
    );

    policy.clear_fallback();
    let after_clear = policy.telemetry();
    assert!(after_clear.fallback_reason.is_none());
    assert_eq!(after_clear.ghost_hits_total, before_clear.ghost_hits_total);
    assert_eq!(
        after_clear.budget_rejections_total,
        before_clear.budget_rejections_total
    );

    let post_clear_reject = policy.access("ext-a", "k5".to_string());
    assert_eq!(
        post_clear_reject.kind,
        S3FifoDecisionKind::RejectFairnessBudget
    );
    let after_reject = policy.telemetry();
    assert_eq!(
        after_reject.budget_rejections_total,
        before_clear.budget_rejections_total + 1
    );
    assert_eq!(after_reject.ghost_hits_total, before_clear.ghost_hits_total);
}

#[test]
fn latched_low_signal_fallback_reason_does_not_flip_under_budget_pressure() {
    let mut policy = S3FifoPolicy::new(S3FifoConfig {
        live_capacity: 8,
        small_capacity: 4,
        ghost_capacity: 8,
        max_entries_per_owner: 1,
        fallback_window: 3,
        min_ghost_hits_in_window: 3,
        max_budget_rejections_in_window: 0,
    });

    let _ = policy.access("ext-a", "ls-1".to_string());
    let _ = policy.access("ext-b", "ls-2".to_string());
    let _ = policy.access("ext-c", "ls-3".to_string());

    let expected_reason = Some(S3FifoFallbackReason::SignalQualityInsufficient);
    assert_eq!(policy.telemetry().fallback_reason, expected_reason);
    let baseline = policy.telemetry();

    for key in ["budget-1", "budget-2", "budget-3"] {
        let decision = policy.access("ext-hot", key.to_string());
        assert_eq!(decision.kind, S3FifoDecisionKind::FallbackBypass);
        assert_eq!(decision.tier, S3FifoTier::Fallback);
        assert_eq!(decision.fallback_reason, expected_reason);
    }

    let after = policy.telemetry();
    assert_eq!(after.fallback_reason, expected_reason);
    assert_eq!(
        after.budget_rejections_total, baseline.budget_rejections_total,
        "bypass while latched must not advance fairness counters"
    );
    assert_eq!(
        after.ghost_hits_total, baseline.ghost_hits_total,
        "bypass while latched must not fabricate ghost-hit signal"
    );
}

#[test]
fn latched_fairness_fallback_reason_does_not_flip_under_low_signal_sequence() {
    let mut policy = S3FifoPolicy::new(S3FifoConfig {
        live_capacity: 2,
        small_capacity: 1,
        ghost_capacity: 8,
        max_entries_per_owner: 1,
        fallback_window: 3,
        min_ghost_hits_in_window: 1,
        max_budget_rejections_in_window: 0,
    });

    let _ = policy.access("ext-b", "ghost-seed".to_string());
    let _ = policy.access("ext-hot", "fair-live".to_string());
    let trigger = policy.access("ext-hot", "ghost-seed".to_string());
    assert_eq!(trigger.kind, S3FifoDecisionKind::RejectFairnessBudget);
    assert!(trigger.ghost_hit);

    let expected_reason = Some(S3FifoFallbackReason::FairnessInstability);
    assert_eq!(policy.telemetry().fallback_reason, expected_reason);
    let baseline = policy.telemetry();

    for (owner, key) in [
        ("ext-a", "cold-1"),
        ("ext-b", "cold-2"),
        ("ext-c", "cold-3"),
    ] {
        let decision = policy.access(owner, key.to_string());
        assert_eq!(decision.kind, S3FifoDecisionKind::FallbackBypass);
        assert_eq!(decision.tier, S3FifoTier::Fallback);
        assert_eq!(decision.fallback_reason, expected_reason);
    }

    let after = policy.telemetry();
    assert_eq!(after.fallback_reason, expected_reason);
    assert_eq!(
        after.budget_rejections_total, baseline.budget_rejections_total,
        "latched fallback should keep fairness counter stable during bypass"
    );
    assert_eq!(
        after.ghost_hits_total, baseline.ghost_hits_total,
        "latched fallback should keep ghost-hit counter stable during bypass"
    );
}

#[test]
fn config_clamps_zero_inputs_to_safe_minima() {
    let policy: S3FifoPolicy<String> = S3FifoPolicy::new(S3FifoConfig {
        live_capacity: 0,
        small_capacity: 0,
        ghost_capacity: 0,
        max_entries_per_owner: 0,
        fallback_window: 0,
        min_ghost_hits_in_window: usize::MAX,
        max_budget_rejections_in_window: usize::MAX,
    });

    let cfg = policy.config();
    assert_eq!(cfg.live_capacity, 2);
    assert_eq!(cfg.small_capacity, 1);
    assert_eq!(cfg.ghost_capacity, 1);
    assert_eq!(cfg.max_entries_per_owner, 1);
    assert_eq!(cfg.fallback_window, 1);
    assert_eq!(cfg.min_ghost_hits_in_window, 1);
    assert_eq!(cfg.max_budget_rejections_in_window, 1);
}

#[test]
fn config_clamps_oversized_small_capacity_to_live_minus_one() {
    let policy: S3FifoPolicy<String> = S3FifoPolicy::new(S3FifoConfig {
        live_capacity: 3,
        small_capacity: usize::MAX,
        ghost_capacity: 8,
        max_entries_per_owner: 3,
        fallback_window: 5,
        min_ghost_hits_in_window: 2,
        max_budget_rejections_in_window: 4,
    });

    let cfg = policy.config();
    assert_eq!(cfg.live_capacity, 3);
    assert_eq!(
        cfg.small_capacity, 2,
        "small capacity must clamp to live_capacity - 1"
    );
    assert_eq!(cfg.ghost_capacity, 8);
    assert_eq!(cfg.max_entries_per_owner, 3);
}

#[test]
fn config_caps_window_thresholds_without_over_clamping_in_range_values() {
    let capped: S3FifoPolicy<String> = S3FifoPolicy::new(S3FifoConfig {
        live_capacity: 16,
        small_capacity: 4,
        ghost_capacity: 16,
        max_entries_per_owner: 16,
        fallback_window: 5,
        min_ghost_hits_in_window: 9,
        max_budget_rejections_in_window: 7,
    });
    let capped_cfg = capped.config();
    assert_eq!(capped_cfg.fallback_window, 5);
    assert_eq!(capped_cfg.min_ghost_hits_in_window, 5);
    assert_eq!(capped_cfg.max_budget_rejections_in_window, 5);

    let preserved: S3FifoPolicy<String> = S3FifoPolicy::new(S3FifoConfig {
        live_capacity: 16,
        small_capacity: 4,
        ghost_capacity: 16,
        max_entries_per_owner: 16,
        fallback_window: 5,
        min_ghost_hits_in_window: 3,
        max_budget_rejections_in_window: 4,
    });
    let preserved_cfg = preserved.config();
    assert_eq!(preserved_cfg.fallback_window, 5);
    assert_eq!(preserved_cfg.min_ghost_hits_in_window, 3);
    assert_eq!(preserved_cfg.max_budget_rejections_in_window, 4);
}

#[test]
fn config_clamps_live_capacity_one_to_two_with_single_small_slot() {
    let policy: S3FifoPolicy<String> = S3FifoPolicy::new(S3FifoConfig {
        live_capacity: 1,
        small_capacity: usize::MAX,
        ghost_capacity: 2,
        max_entries_per_owner: 2,
        fallback_window: 4,
        min_ghost_hits_in_window: 0,
        max_budget_rejections_in_window: 0,
    });

    let cfg = policy.config();
    assert_eq!(cfg.live_capacity, 2);
    assert_eq!(cfg.small_capacity, 1);
    assert_eq!(cfg.ghost_capacity, 2);
    assert_eq!(cfg.fallback_window, 4);
}

#[test]
fn config_clamps_small_capacity_equal_to_live_capacity_down_by_one() {
    let policy: S3FifoPolicy<String> = S3FifoPolicy::new(S3FifoConfig {
        live_capacity: 2,
        small_capacity: 2,
        ghost_capacity: 2,
        max_entries_per_owner: 2,
        fallback_window: 2,
        min_ghost_hits_in_window: 0,
        max_budget_rejections_in_window: 0,
    });

    let cfg = policy.config();
    assert_eq!(cfg.live_capacity, 2);
    assert_eq!(cfg.small_capacity, 1);
    assert_eq!(cfg.ghost_capacity, 2);
}

#[test]
fn fairness_fallback_never_triggers_when_budget_threshold_clamps_to_window_size() {
    let mut policy = S3FifoPolicy::new(S3FifoConfig {
        live_capacity: 8,
        small_capacity: 4,
        ghost_capacity: 8,
        max_entries_per_owner: 1,
        fallback_window: 3,
        min_ghost_hits_in_window: 0,
        max_budget_rejections_in_window: usize::MAX,
    });

    let cfg = policy.config();
    assert_eq!(cfg.max_budget_rejections_in_window, cfg.fallback_window);

    let seed = policy.access("ext-a", "seed".to_string());
    assert_eq!(seed.kind, S3FifoDecisionKind::AdmitSmall);

    for idx in 0..8 {
        let decision = policy.access("ext-a", format!("overflow-{idx}"));
        assert_eq!(decision.kind, S3FifoDecisionKind::RejectFairnessBudget);
        assert_eq!(
            policy.telemetry().fallback_reason,
            None,
            "strictly-greater fairness threshold cannot trip when clamped to window length"
        );
    }
}

#[test]
fn repeated_clear_fallback_cycles_require_new_full_windows() {
    let mut policy = S3FifoPolicy::new(S3FifoConfig {
        live_capacity: 8,
        small_capacity: 4,
        ghost_capacity: 8,
        max_entries_per_owner: 8,
        fallback_window: 2,
        min_ghost_hits_in_window: 2,
        max_budget_rejections_in_window: 2,
    });

    let _ = policy.access("ext-a", "cold-1".to_string());
    let _ = policy.access("ext-b", "cold-2".to_string());
    assert_eq!(
        policy.telemetry().fallback_reason,
        Some(S3FifoFallbackReason::SignalQualityInsufficient)
    );

    let bypass_1 = policy.access("ext-c", "while-1".to_string());
    assert_eq!(bypass_1.kind, S3FifoDecisionKind::FallbackBypass);

    policy.clear_fallback();
    assert!(policy.telemetry().fallback_reason.is_none());

    let after_clear_1 = policy.access("ext-d", "cold-3".to_string());
    assert_ne!(after_clear_1.kind, S3FifoDecisionKind::FallbackBypass);
    assert!(
        policy.telemetry().fallback_reason.is_none(),
        "window should restart after clear; one event cannot retrigger with fallback_window=2"
    );

    let _ = policy.access("ext-e", "cold-4".to_string());
    assert_eq!(
        policy.telemetry().fallback_reason,
        Some(S3FifoFallbackReason::SignalQualityInsufficient)
    );

    let bypass_2 = policy.access("ext-f", "while-2".to_string());
    assert_eq!(bypass_2.kind, S3FifoDecisionKind::FallbackBypass);

    policy.clear_fallback();
    assert!(policy.telemetry().fallback_reason.is_none());

    let after_clear_2 = policy.access("ext-g", "cold-5".to_string());
    assert_ne!(after_clear_2.kind, S3FifoDecisionKind::FallbackBypass);
    assert!(
        policy.telemetry().fallback_reason.is_none(),
        "each clear should force a fresh full-window evidence cycle"
    );
}

#[test]
fn single_window_fairness_retrigger_requires_new_rejection_after_clear() {
    let mut policy = S3FifoPolicy::new(S3FifoConfig {
        live_capacity: 8,
        small_capacity: 4,
        ghost_capacity: 8,
        max_entries_per_owner: 1,
        fallback_window: 1,
        min_ghost_hits_in_window: 0,
        max_budget_rejections_in_window: 0,
    });

    let seed = policy.access("ext-a", "seed".to_string());
    assert_eq!(seed.kind, S3FifoDecisionKind::AdmitSmall);
    assert_eq!(policy.telemetry().fallback_reason, None);

    let trigger = policy.access("ext-a", "overflow-1".to_string());
    assert_eq!(trigger.kind, S3FifoDecisionKind::RejectFairnessBudget);
    assert_eq!(
        policy.telemetry().fallback_reason,
        Some(S3FifoFallbackReason::FairnessInstability)
    );

    policy.clear_fallback();
    assert_eq!(policy.telemetry().fallback_reason, None);

    let post_clear_admit = policy.access("ext-b", "fresh".to_string());
    assert_ne!(post_clear_admit.kind, S3FifoDecisionKind::FallbackBypass);
    assert_eq!(policy.telemetry().fallback_reason, None);

    let retrigger = policy.access("ext-a", "overflow-2".to_string());
    assert_eq!(retrigger.kind, S3FifoDecisionKind::RejectFairnessBudget);
    assert_eq!(
        policy.telemetry().fallback_reason,
        Some(S3FifoFallbackReason::FairnessInstability)
    );
}

#[test]
fn clear_fallback_preserves_owner_and_live_depth_telemetry_state() {
    let mut policy = S3FifoPolicy::new(S3FifoConfig {
        live_capacity: 8,
        small_capacity: 4,
        ghost_capacity: 8,
        max_entries_per_owner: 8,
        fallback_window: 2,
        min_ghost_hits_in_window: 2,
        max_budget_rejections_in_window: 2,
    });

    let _ = policy.access("ext-a", "cold-1".to_string());
    let _ = policy.access("ext-b", "cold-2".to_string());
    assert_eq!(
        policy.telemetry().fallback_reason,
        Some(S3FifoFallbackReason::SignalQualityInsufficient)
    );

    let before_clear = policy.telemetry();
    assert_eq!(before_clear.live_depth, 2);
    assert_eq!(before_clear.owner_live_counts.get("ext-a"), Some(&1));
    assert_eq!(before_clear.owner_live_counts.get("ext-b"), Some(&1));

    policy.clear_fallback();
    let after_clear = policy.telemetry();

    assert!(after_clear.fallback_reason.is_none());
    assert_eq!(after_clear.live_depth, before_clear.live_depth);
    assert_eq!(after_clear.small_depth, before_clear.small_depth);
    assert_eq!(after_clear.main_depth, before_clear.main_depth);
    assert_eq!(after_clear.ghost_depth, before_clear.ghost_depth);
    assert_eq!(
        after_clear.owner_live_counts,
        before_clear.owner_live_counts
    );
    assert_eq!(after_clear.admissions_total, before_clear.admissions_total);
    assert_eq!(after_clear.promotions_total, before_clear.promotions_total);
    assert_eq!(after_clear.ghost_hits_total, before_clear.ghost_hits_total);
    assert_eq!(
        after_clear.budget_rejections_total,
        before_clear.budget_rejections_total
    );

    let post_clear = policy.access("ext-c", "fresh-1".to_string());
    assert_ne!(post_clear.kind, S3FifoDecisionKind::FallbackBypass);
    assert!(
        policy.telemetry().fallback_reason.is_none(),
        "fallback window should restart after clear"
    );
}
