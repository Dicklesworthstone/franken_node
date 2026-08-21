use frankenengine_node::security::revocation_freshness::{
    FreshnessCheck, FreshnessError, FreshnessPolicy, OverrideReceipt, SafetyTier,
    evaluate_default_freshness, evaluate_freshness, snapshot_age_secs, snapshot_age_secs_for_path,
    unix_mtime_epoch_secs,
};

fn policy() -> FreshnessPolicy {
    FreshnessPolicy {
        risky_max_age_secs: 3600,
        dangerous_max_age_secs: 300,
    }
}

fn check(tier: SafetyTier, age: u64) -> FreshnessCheck {
    FreshnessCheck {
        action_id: "action-a".to_string(),
        tier,
        revocation_age_secs: age,
        trace_id: "trace-a".to_string(),
        timestamp: "2026-04-25T01:00:00Z".to_string(),
    }
}

fn override_receipt() -> OverrideReceipt {
    OverrideReceipt {
        action_id: "action-a".to_string(),
        actor: "operator-a".to_string(),
        reason: "break-glass maintenance".to_string(),
        timestamp: "2026-04-25T01:01:00Z".to_string(),
        trace_id: "trace-a".to_string(),
    }
}

#[test]
fn invalid_policy_is_rejected_before_decision() {
    let invalid_policy = FreshnessPolicy {
        risky_max_age_secs: 10,
        dangerous_max_age_secs: 11,
    };

    let err = evaluate_freshness(
        &invalid_policy,
        &check(SafetyTier::Dangerous, 1),
        Some(&override_receipt()),
    )
    .expect_err("invalid policy must fail closed before evaluation");

    assert_eq!(
        err,
        FreshnessError::PolicyInvalid {
            reason: "dangerous_max_age must be <= risky_max_age".to_string(),
        }
    );
}

#[test]
fn standard_tier_rejects_whitespace_padded_action_id() {
    let mut malformed = check(SafetyTier::Standard, 0);
    malformed.action_id = " action-a".to_string();

    let err =
        evaluate_freshness(&policy(), &malformed, None).expect_err("malformed check must fail");

    assert_eq!(
        err,
        FreshnessError::PolicyInvalid {
            reason: "freshness check action_id must not contain leading or trailing whitespace"
                .to_string(),
        }
    );
}

#[test]
fn fresh_risky_action_rejects_control_character_trace_id() {
    let mut malformed = check(SafetyTier::Risky, 1);
    malformed.trace_id = "trace-a\n".to_string();

    let err = evaluate_freshness(&policy(), &malformed, None).expect_err("control chars must fail");

    assert_eq!(
        err,
        FreshnessError::PolicyInvalid {
            reason: "freshness check trace_id must not contain leading or trailing whitespace"
                .to_string(),
        }
    );
}

#[test]
fn stale_override_rejects_actor_with_trailing_space() {
    let stale = check(SafetyTier::Risky, 7200);
    let mut receipt = override_receipt();
    receipt.actor = "operator-a ".to_string();

    let err = evaluate_freshness(&policy(), &stale, Some(&receipt))
        .expect_err("invalid override metadata must fail closed");

    assert_eq!(
        err,
        FreshnessError::OverrideRequired {
            tier: "Risky".to_string(),
            age_secs: 7200,
        }
    );
}

#[test]
fn policy_mode_maps_onto_product_tiers() {
    assert_eq!(SafetyTier::for_policy_mode("strict"), SafetyTier::Dangerous);
    assert_eq!(SafetyTier::for_policy_mode("balanced"), SafetyTier::Risky);
    assert_eq!(
        SafetyTier::for_policy_mode("legacy-risky"),
        SafetyTier::Standard
    );
}

#[test]
fn snapshot_age_saturates_when_clock_is_behind_mtime() {
    assert_eq!(snapshot_age_secs(1_700_000_000, 2_000), 0);
    assert_eq!(snapshot_age_secs(1_000, 4_601), 3_601);
}

#[test]
fn default_freshness_denies_stale_dangerous_actions() {
    let err = evaluate_default_freshness(
        "remotecap-issue",
        SafetyTier::Dangerous,
        301,
        "tr-default",
        "ts-default",
    )
    .expect_err("stale dangerous must fail closed");
    assert!(matches!(
        err,
        FreshnessError::StaleFrontier {
            age_secs: 301,
            max_age_secs: 300,
            ..
        }
    ));
}

#[test]
fn unix_mtime_none_for_missing_path() {
    assert!(
        unix_mtime_epoch_secs(std::path::Path::new("/no/such/revocation-snapshot.json")).is_none()
    );
    assert!(
        snapshot_age_secs_for_path(std::path::Path::new("/no/such/revocation-snapshot.json"), 9)
            .is_none()
    );
}
