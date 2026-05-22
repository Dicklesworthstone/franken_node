//! Integration tests for bd-3ps8 — Mergeable sketch system.
//!
//! These tests exercise the *public* surface of
//! `frankenengine_node::federation::atc_sketches`. The matching in-source
//! `#[cfg(test)] mod tests` block in `atc_sketches.rs` covers private-field
//! invariants; this file covers the contract-level behavior gated by the
//! bead's acceptance criterion ("deterministic, bounded-error, budget-
//! respecting merge under large participant counts").

#![cfg(feature = "advanced-features")]

use frankenengine_node::federation::atc_reciprocity::{
    AccessDecision, AccessTier, ContributionMetrics, ReciprocityConfig, ReciprocityEngine,
    event_codes as reciprocity_events, invariants as reciprocity_invariants,
};
use frankenengine_node::federation::atc_sketches::{
    BudgetTracker, CountMinSketch, DEFAULT_BANDWIDTH_BYTES, DEFAULT_COMPUTE_OPS, ErrorBound,
    MAX_BUDGET_EVENTS, MAX_CMS_DEPTH, MAX_CMS_WIDTH, MergeableSketch, SketchError,
    compute_error_bound,
};

const RECIPROCITY_NOW: &str = "2026-04-17T00:00:00Z";
const RECIPROCITY_FUTURE: &str = "2027-01-01T00:00:00Z";
const RECIPROCITY_PAST: &str = "2025-01-01T00:00:00Z";
const ESTABLISHED_AGE_SECONDS: u64 = 86400 * 30;

fn small_cms() -> CountMinSketch {
    CountMinSketch::new(4, 64).expect("dims valid")
}

fn reciprocity_metrics(
    participant_id: &str,
    contributions_made: u64,
    intelligence_consumed: u64,
    contribution_quality: f64,
    membership_age_seconds: u64,
) -> ContributionMetrics {
    ContributionMetrics {
        participant_id: participant_id.to_string(),
        contributions_made,
        intelligence_consumed,
        contribution_quality,
        membership_age_seconds,
        has_exception: false,
        exception_reason: None,
        exception_expires_at: None,
    }
}

fn no_grace_reciprocity_config() -> ReciprocityConfig {
    ReciprocityConfig {
        grace_period_seconds: 0,
        ..ReciprocityConfig::default()
    }
}

fn reciprocity_decision(metrics: &ContributionMetrics) -> AccessDecision {
    let mut engine = ReciprocityEngine::new(no_grace_reciprocity_config());
    engine.evaluate_access(metrics, RECIPROCITY_NOW)
}

fn last_reciprocity_event(engine: &ReciprocityEngine) -> Option<&str> {
    engine
        .audit_log()
        .last()
        .map(|entry| entry.event_code.as_str())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn record_reciprocity_requirement(
    requirements: &mut Vec<(&'static str, &'static str, bool)>,
    id: &'static str,
    clause: &'static str,
    passed: bool,
) {
    requirements.push((id, clause, passed));
}

#[test]
fn deterministic_construction_same_dimensions() {
    // Two independently constructed CMS with identical dims must hash to the
    // same column for every key — proves seed determinism via behavior.
    let a = CountMinSketch::new(5, 128).unwrap();
    let b = CountMinSketch::new(5, 128).unwrap();
    for i in 0..50u32 {
        let key = format!("test-{i}");
        assert_eq!(a.estimate(key.as_bytes()), b.estimate(key.as_bytes()));
    }
    // After identical inserts, sketches must remain bit-identical (via JSON).
    let mut a = a;
    let mut b = b;
    for i in 0..50u32 {
        let key = format!("test-{i}");
        a.insert(key.as_bytes());
        b.insert(key.as_bytes());
    }
    let aj = serde_json::to_string(&a).unwrap();
    let bj = serde_json::to_string(&b).unwrap();
    assert_eq!(aj, bj);
}

#[test]
fn merge_is_commutative_observable() {
    let mut left = small_cms();
    let mut right = small_cms();
    left.add(b"alpha", 3);
    left.add(b"beta", 7);
    right.add(b"alpha", 11);
    right.add(b"gamma", 5);

    let mut ab = left.clone();
    ab.merge(&right).unwrap();
    let mut ba = right.clone();
    ba.merge(&left).unwrap();

    for key in [b"alpha".as_slice(), b"beta", b"gamma", b"delta"] {
        assert_eq!(ab.estimate(key), ba.estimate(key));
    }
}

#[test]
fn merge_is_associative_observable() {
    let mut a = small_cms();
    let mut b = small_cms();
    let mut c = small_cms();
    a.add(b"x", 2);
    b.add(b"y", 3);
    c.add(b"z", 5);

    let mut left = a.clone();
    left.merge(&b).unwrap();
    left.merge(&c).unwrap();

    let mut right = b.clone();
    right.merge(&c).unwrap();
    let mut combined = a.clone();
    combined.merge(&right).unwrap();

    for key in [b"x".as_slice(), b"y", b"z", b"missing"] {
        assert_eq!(left.estimate(key), combined.estimate(key));
    }
}

#[test]
fn empty_merge_is_identity_observable() {
    let mut populated = small_cms();
    populated.add(b"hello", 42);

    let empty = small_cms();
    let mut merged = populated.clone();
    merged.merge(&empty).unwrap();
    assert_eq!(merged.estimate(b"hello"), populated.estimate(b"hello"));

    let mut merged2 = empty.clone();
    merged2.merge(&populated).unwrap();
    assert_eq!(merged2.estimate(b"hello"), populated.estimate(b"hello"));
}

#[test]
fn merge_dimension_mismatch_fails_closed() {
    let mut a = CountMinSketch::new(4, 64).unwrap();
    let b = CountMinSketch::new(5, 64).unwrap();
    let err = a.merge(&b).unwrap_err();
    assert!(matches!(err, SketchError::DimensionMismatch { .. }));
    assert!(format!("{err}").contains("ATC-SKETCH-ERR-001"));
}

#[test]
fn invalid_dimensions_rejected() {
    assert!(matches!(
        CountMinSketch::new(0, 64).unwrap_err(),
        SketchError::InvalidDimensions { .. }
    ));
    assert!(matches!(
        CountMinSketch::new(4, 0).unwrap_err(),
        SketchError::InvalidDimensions { .. }
    ));
    assert!(matches!(
        CountMinSketch::new(MAX_CMS_DEPTH + 1, 64).unwrap_err(),
        SketchError::InvalidDimensions { .. }
    ));
    assert!(matches!(
        CountMinSketch::new(4, MAX_CMS_WIDTH + 1).unwrap_err(),
        SketchError::InvalidDimensions { .. }
    ));
}

#[test]
fn saturating_add_no_overflow_panic() {
    let mut a = small_cms();
    a.add(b"saturate-me", u64::MAX);
    a.add(b"saturate-me", u64::MAX);
    assert_eq!(a.estimate(b"saturate-me"), u64::MAX);

    // Merge of two saturated sketches must not panic.
    let mut b = a.clone();
    b.merge(&a).unwrap();
    assert_eq!(b.estimate(b"saturate-me"), u64::MAX);
}

#[test]
fn error_bound_matches_theory() {
    let bound = compute_error_bound(7, 2719).unwrap();
    assert!((bound.eps - std::f64::consts::E / 2719.0).abs() < 1e-12);
    assert!((bound.delta - (-7.0_f64).exp()).abs() < 1e-12);
    let conf = bound.confidence_pct();
    assert!((0.0..=100.0).contains(&conf));
}

#[test]
fn error_bound_invalid_dimensions_fail_closed() {
    assert!(compute_error_bound(0, 64).is_err());
    assert!(compute_error_bound(4, 0).is_err());
    assert!(compute_error_bound(MAX_CMS_DEPTH + 1, 64).is_err());
}

#[test]
fn for_bounds_rejects_non_finite_params() {
    assert!(CountMinSketch::for_bounds(f64::NAN, 0.01).is_err());
    assert!(CountMinSketch::for_bounds(0.01, f64::INFINITY).is_err());
    assert!(CountMinSketch::for_bounds(-0.5, 0.01).is_err());
    assert!(CountMinSketch::for_bounds(0.01, 2.0).is_err());
}

#[test]
fn for_bounds_picks_reasonable_dimensions() {
    let s = CountMinSketch::for_bounds(0.01, 0.01).unwrap();
    assert!(s.width() >= (std::f64::consts::E / 0.01).ceil() as u32);
    assert!(s.depth() >= 1);
    assert!(s.depth() <= MAX_CMS_DEPTH);
}

#[test]
fn estimate_is_upper_bound_on_true_count() {
    let mut s = CountMinSketch::for_bounds(0.05, 0.05).unwrap();
    for i in 0..500u32 {
        s.insert(format!("item-{i}").as_bytes());
    }
    // CMS estimator never undercounts.
    let est = s.estimate(b"item-42");
    assert!(est >= 1, "estimate {est} < true 1");
}

#[test]
fn serialization_round_trip_preserves_estimates() {
    let mut s = small_cms();
    for i in 0..20u32 {
        s.insert(format!("k{i}").as_bytes());
    }
    let bytes = serde_json::to_vec(&s).unwrap();
    let parsed: CountMinSketch = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed.depth(), s.depth());
    assert_eq!(parsed.width(), s.width());
    for i in 0..20u32 {
        let key = format!("k{i}");
        assert_eq!(parsed.estimate(key.as_bytes()), s.estimate(key.as_bytes()));
    }
}

#[test]
fn serialized_size_is_positive_and_dimension_proportional() {
    let small = CountMinSketch::new(2, 16).unwrap();
    let big = CountMinSketch::new(4, 256).unwrap();
    assert!(small.serialized_size() > 0);
    assert!(big.serialized_size() > small.serialized_size());
}

#[test]
fn bandwidth_budget_caps_transport() {
    let s = CountMinSketch::new(4, 64).unwrap();
    let bytes = s.serialized_size() as u64;
    // Cap fits exactly one sketch; the second charge must fail closed.
    let mut tracker = BudgetTracker::new(bytes, DEFAULT_COMPUTE_OPS);
    assert!(tracker.charge_bandwidth(bytes).is_ok());
    let err = tracker.charge_bandwidth(bytes).unwrap_err();
    assert!(matches!(err, SketchError::BandwidthExceeded { .. }));
    assert!(format!("{err}").contains("ATC-SKETCH-ERR-002"));
    assert!(tracker.events().iter().any(|e| e.contains("ERR-002")));
}

#[test]
fn compute_budget_caps_insertions() {
    let mut tracker = BudgetTracker::new(DEFAULT_BANDWIDTH_BYTES, 100);
    for _ in 0..100 {
        tracker.charge_compute(1).unwrap();
    }
    let err = tracker.charge_compute(1).unwrap_err();
    assert!(matches!(err, SketchError::ComputeExceeded { .. }));
    assert_eq!(tracker.compute_remaining(), 0);
}

#[test]
fn budget_event_log_is_bounded() {
    let mut tracker = BudgetTracker::new(u64::MAX, u64::MAX);
    for _ in 0..(MAX_BUDGET_EVENTS + 200) {
        tracker.charge_compute(1).unwrap();
    }
    assert!(tracker.events().len() <= MAX_BUDGET_EVENTS);
}

#[test]
fn many_participant_merge_respects_budget() {
    let n_participants = 1000u32;
    let mut global = CountMinSketch::new(4, 256).unwrap();
    let per_size = global.serialized_size() as u64;
    // Provision the bandwidth budget for exactly n_participants sketches.
    let bandwidth_cap = per_size.saturating_mul(n_participants as u64);
    let mut tracker = BudgetTracker::new(bandwidth_cap, (n_participants as u64).saturating_mul(50));
    for p in 0..n_participants {
        tracker.charge_bandwidth(per_size).unwrap();
        tracker.charge_compute(10).unwrap();
        let mut local = CountMinSketch::new(4, 256).unwrap();
        local.insert(format!("attacker-{}", p % 50).as_bytes());
        global.merge(&local).unwrap();
    }
    // Each attacker-X observed n/50 = 20 times globally; CMS is upper-bound.
    assert!(global.estimate(b"attacker-7") >= 20);
    // Budget fully consumed (bandwidth) but not exceeded.
    assert_eq!(tracker.bandwidth_remaining(), 0);
    // One more charge must fail closed.
    let err = tracker.charge_bandwidth(per_size).unwrap_err();
    assert!(matches!(err, SketchError::BandwidthExceeded { .. }));
}

#[test]
fn confidence_pct_is_in_range() {
    let high = ErrorBound {
        eps: 0.01,
        delta: 1e-9,
    };
    let low = ErrorBound {
        eps: 0.01,
        delta: 0.999,
    };
    assert!(high.confidence_pct() > low.confidence_pct());
    assert!((0.0..=100.0).contains(&high.confidence_pct()));
    assert!((0.0..=100.0).contains(&low.confidence_pct()));
}

#[test]
fn atc_reciprocity_policy_conformance_matrix_covers_core_musts() {
    let mut requirements = Vec::new();

    let deterministic_metrics =
        reciprocity_metrics("deterministic", 80, 100, 1.0, ESTABLISHED_AGE_SECONDS);
    let first_decision = reciprocity_decision(&deterministic_metrics);
    let second_decision = reciprocity_decision(&deterministic_metrics);
    record_reciprocity_requirement(
        &mut requirements,
        reciprocity_invariants::INV_ATC_RECIPROCITY_DETERMINISM,
        "same contribution data must produce the same access decision",
        first_decision == second_decision && first_decision.tier == AccessTier::Full,
    );

    let mut monotone_engine = ReciprocityEngine::new(no_grace_reciprocity_config());
    let observed_tiers: Vec<AccessTier> = [0_u64, 10, 40, 80, 100]
        .into_iter()
        .map(|contributions_made| {
            let metrics = reciprocity_metrics(
                &format!("tier-{contributions_made}"),
                contributions_made,
                100,
                1.0,
                ESTABLISHED_AGE_SECONDS,
            );
            monotone_engine
                .evaluate_access(&metrics, RECIPROCITY_NOW)
                .tier
        })
        .collect();
    record_reciprocity_requirement(
        &mut requirements,
        reciprocity_invariants::INV_ATC_TIER_MONOTONE,
        "higher contribution ratios must not produce lower access tiers",
        observed_tiers.windows(2).all(|pair| match pair {
            [left, right] => left <= right,
            _ => false,
        }) && observed_tiers
            == [
                AccessTier::Blocked,
                AccessTier::Limited,
                AccessTier::Standard,
                AccessTier::Full,
                AccessTier::Full,
            ],
    );

    let mut freerider_engine = ReciprocityEngine::new(no_grace_reciprocity_config());
    let freerider_metrics = reciprocity_metrics("freerider", 1, 500, 1.0, ESTABLISHED_AGE_SECONDS);
    let freerider_decision = freerider_engine.evaluate_access(&freerider_metrics, RECIPROCITY_NOW);
    record_reciprocity_requirement(
        &mut requirements,
        reciprocity_invariants::INV_ATC_FREERIDER_BOUND,
        "participants below the minimum ratio must be denied protected feeds",
        freerider_decision.tier == AccessTier::Blocked
            && !freerider_decision.granted
            && freerider_decision.accessible_feeds.is_empty()
            && last_reciprocity_event(&freerider_engine) == Some(reciprocity_events::ACCESS_DENIED),
    );

    let failed_closed_exceptions = [None, Some("not-rfc3339"), Some(RECIPROCITY_PAST)]
        .into_iter()
        .all(|expires_at| {
            let mut metrics =
                reciprocity_metrics("expired-exception", 0, 100, 0.0, ESTABLISHED_AGE_SECONDS);
            metrics.has_exception = true;
            metrics.exception_reason = Some("research access".to_string());
            metrics.exception_expires_at = expires_at.map(str::to_string);

            let mut engine = ReciprocityEngine::new(no_grace_reciprocity_config());
            let decision = engine.evaluate_access(&metrics, RECIPROCITY_NOW);
            decision.tier == AccessTier::Blocked
                && !decision.granted
                && !decision.exception_applied
                && last_reciprocity_event(&engine) == Some(reciprocity_events::ACCESS_DENIED)
        });

    let mut exception_metrics =
        reciprocity_metrics("active-exception", 0, 100, 0.0, ESTABLISHED_AGE_SECONDS);
    exception_metrics.has_exception = true;
    exception_metrics.exception_reason = Some("approved audit".to_string());
    exception_metrics.exception_expires_at = Some(RECIPROCITY_FUTURE.to_string());
    let mut exception_engine = ReciprocityEngine::new(no_grace_reciprocity_config());
    let exception_decision = exception_engine.evaluate_access(&exception_metrics, RECIPROCITY_NOW);
    record_reciprocity_requirement(
        &mut requirements,
        reciprocity_invariants::INV_ATC_EXCEPTION_AUDITED,
        "only unexpired exceptions may grant access and every grant must be audited",
        failed_closed_exceptions
            && exception_decision.tier == AccessTier::Standard
            && exception_decision.granted
            && exception_decision.exception_applied
            && exception_engine.audit_log().len() == 1
            && last_reciprocity_event(&exception_engine)
                == Some(reciprocity_events::EXCEPTION_ACTIVATED),
    );

    let grace_config = ReciprocityConfig {
        grace_period_seconds: 10,
        grace_period_tier: AccessTier::Limited,
        ..ReciprocityConfig::default()
    };
    let mut grace_engine = ReciprocityEngine::new(grace_config.clone());
    let grace_before_boundary = reciprocity_metrics("grace-before", 0, 100, 0.0, 9);
    let grace_decision = grace_engine.evaluate_access(&grace_before_boundary, RECIPROCITY_NOW);
    let mut boundary_engine = ReciprocityEngine::new(grace_config);
    let grace_at_boundary = reciprocity_metrics("grace-boundary", 0, 100, 0.0, 10);
    let boundary_decision = boundary_engine.evaluate_access(&grace_at_boundary, RECIPROCITY_NOW);
    record_reciprocity_requirement(
        &mut requirements,
        reciprocity_invariants::INV_ATC_GRACE_BOUNDED,
        "grace access must stop at the configured finite boundary",
        grace_decision.grace_period_active
            && grace_decision.tier == AccessTier::Limited
            && last_reciprocity_event(&grace_engine)
                == Some(reciprocity_events::GRACE_PERIOD_GRANTED)
            && !boundary_decision.grace_period_active
            && boundary_decision.tier == AccessTier::Blocked,
    );

    record_reciprocity_requirement(
        &mut requirements,
        reciprocity_invariants::INV_ATC_ACCESS_LOGGED,
        "every access decision must emit a content-addressed audit record",
        freerider_engine.audit_log().len() == 1
            && freerider_engine.audit_log().last().is_some_and(|entry| {
                entry.decision == freerider_decision && is_sha256_hex(&entry.content_hash)
            }),
    );

    let mut batch_engine = ReciprocityEngine::new(ReciprocityConfig {
        grace_period_seconds: 10,
        grace_period_tier: AccessTier::Standard,
        ..ReciprocityConfig::default()
    });
    let batch_metrics = vec![
        reciprocity_metrics("batch-full", 100, 100, 1.0, ESTABLISHED_AGE_SECONDS),
        reciprocity_metrics("batch-limited", 10, 100, 1.0, ESTABLISHED_AGE_SECONDS),
        freerider_metrics,
        exception_metrics,
        reciprocity_metrics("batch-grace", 0, 100, 0.0, 1),
    ];
    let matrix = batch_engine.evaluate_batch(
        &batch_metrics,
        "atc-reciprocity-conformance",
        RECIPROCITY_NOW,
    );
    let tier_total: usize = matrix.tier_distribution.values().copied().sum();
    let blocked_entries = matrix
        .entries
        .iter()
        .filter(|entry| entry.tier == AccessTier::Blocked)
        .count();
    let exception_entries = matrix
        .entries
        .iter()
        .filter(|entry| entry.exception_active)
        .count();
    record_reciprocity_requirement(
        &mut requirements,
        "ATC-RCP-MATRIX-ACCOUNTING",
        "batch reciprocity matrix totals and integrity hash must match evaluated entries",
        matrix.total_participants == batch_metrics.len()
            && matrix.entries.len() == batch_metrics.len()
            && tier_total == matrix.total_participants
            && matrix.freeriders_blocked == blocked_entries
            && matrix.exceptions_active == exception_entries
            && matrix.exceptions_active == 1
            && is_sha256_hex(&matrix.content_hash),
    );

    let failures: Vec<String> = requirements
        .iter()
        .filter(|(_, _, passed)| !passed)
        .map(|(id, clause, _)| format!("{id}: {clause}"))
        .collect();

    assert_eq!(requirements.len(), 7);
    assert!(
        failures.is_empty(),
        "ATC reciprocity conformance failures: {}",
        failures.join("; ")
    );
}
