//! Security tests for bd-1m8r: Revocation freshness gate per safety tier.
//!
//! Verifies that stale revocation data blocks risky/dangerous actions,
//! standard tier always passes, overrides produce receipts, and all
//! decisions are auditable.

use frankenengine_node::security::revocation_freshness::*;

fn pol() -> FreshnessPolicy {
    FreshnessPolicy {
        risky_max_age_secs: 3600,
        dangerous_max_age_secs: 300,
    }
}

fn chk(tier: SafetyTier, age: u64) -> FreshnessCheck {
    FreshnessCheck {
        action_id: "act-sec".into(),
        tier,
        revocation_age_secs: age,
        trace_id: "tr-sec".into(),
        timestamp: "ts-sec".into(),
    }
}

fn receipt() -> OverrideReceipt {
    OverrideReceipt {
        action_id: "act-sec".into(),
        actor: "sec-admin".into(),
        reason: "approved emergency".into(),
        timestamp: "ts-override".into(),
        trace_id: "tr-sec".into(),
    }
}

#[test]
fn inv_rf_standard_pass_any_age() {
    let d = evaluate_freshness(&pol(), &chk(SafetyTier::Standard, 1_000_000), None).unwrap();
    assert!(d.allowed, "INV-RF-STANDARD-PASS violated");
}

#[test]
fn inv_rf_tier_gate_risky_denies_stale() {
    let err = evaluate_freshness(&pol(), &chk(SafetyTier::Risky, 7200), None).unwrap_err();
    assert_eq!(err.code(), "RF_STALE_FRONTIER", "INV-RF-TIER-GATE violated");
}

#[test]
fn inv_rf_tier_gate_dangerous_denies_stale() {
    let err = evaluate_freshness(&pol(), &chk(SafetyTier::Dangerous, 600), None).unwrap_err();
    assert_eq!(
        err.code(),
        "RF_STALE_FRONTIER",
        "INV-RF-TIER-GATE violated for Dangerous"
    );
}

#[test]
fn inv_rf_override_receipt_present() {
    let d = evaluate_freshness(&pol(), &chk(SafetyTier::Risky, 7200), Some(&receipt())).unwrap();
    assert!(d.allowed, "INV-RF-OVERRIDE-RECEIPT: override should allow");
    let r = d.override_receipt.expect("receipt must be present");
    assert_eq!(r.actor, "sec-admin");
    assert!(!r.reason.is_empty());
}

#[test]
fn inv_rf_audit_decision_has_trace() {
    let d = evaluate_freshness(&pol(), &chk(SafetyTier::Standard, 0), None).unwrap();
    assert_eq!(d.trace_id, "tr-sec", "INV-RF-AUDIT violated");
}

#[test]
fn risky_fresh_allowed() {
    let d = evaluate_freshness(&pol(), &chk(SafetyTier::Risky, 1000), None).unwrap();
    assert!(d.allowed);
}

#[test]
fn dangerous_fresh_allowed() {
    let d = evaluate_freshness(&pol(), &chk(SafetyTier::Dangerous, 100), None).unwrap();
    assert!(d.allowed);
}

#[test]
fn dangerous_override_allowed() {
    let d = evaluate_freshness(&pol(), &chk(SafetyTier::Dangerous, 600), Some(&receipt())).unwrap();
    assert!(d.allowed);
    assert!(d.override_receipt.is_some());
}

#[test]
fn boundary_risky_exactly_at_max() {
    let d = evaluate_freshness(&pol(), &chk(SafetyTier::Risky, 3600), None).unwrap();
    assert!(d.allowed);
}

#[test]
fn boundary_dangerous_exactly_at_max() {
    let d = evaluate_freshness(&pol(), &chk(SafetyTier::Dangerous, 300), None).unwrap();
    assert!(d.allowed);
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
    assert_eq!(err.code(), "RF_STALE_FRONTIER");
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
