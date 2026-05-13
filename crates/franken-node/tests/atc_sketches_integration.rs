//! Integration tests for bd-3ps8 — Mergeable sketch system.
//!
//! These tests exercise the *public* surface of
//! `frankenengine_node::federation::atc_sketches`. The matching in-source
//! `#[cfg(test)] mod tests` block in `atc_sketches.rs` covers private-field
//! invariants; this file covers the contract-level behavior gated by the
//! bead's acceptance criterion ("deterministic, bounded-error, budget-
//! respecting merge under large participant counts").

#![cfg(feature = "advanced-features")]

use frankenengine_node::federation::atc_sketches::{
    BudgetTracker, CountMinSketch, DEFAULT_BANDWIDTH_BYTES, DEFAULT_COMPUTE_OPS, ErrorBound,
    MAX_BUDGET_EVENTS, MAX_CMS_DEPTH, MAX_CMS_WIDTH, MergeableSketch, SketchError,
    compute_error_bound,
};

fn small_cms() -> CountMinSketch {
    CountMinSketch::new(4, 64).expect("dims valid")
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
    let mut tracker = BudgetTracker::new(
        bandwidth_cap,
        (n_participants as u64).saturating_mul(50),
    );
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
    let high = ErrorBound { eps: 0.01, delta: 1e-9 };
    let low = ErrorBound { eps: 0.01, delta: 0.999 };
    assert!(high.confidence_pct() > low.confidence_pct());
    assert!((0.0..=100.0).contains(&high.confidence_pct()));
    assert!((0.0..=100.0).contains(&low.confidence_pct()));
}
