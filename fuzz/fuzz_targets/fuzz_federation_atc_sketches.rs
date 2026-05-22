#![no_main]
#![forbid(unsafe_code)]

//! Structure-aware fuzzing for federation ATC sketch primitives.
//!
//! This target keeps each iteration bounded while checking public invariants
//! of `CountMinSketch` and `BudgetTracker`: deterministic dimensions, finite
//! error bounds, conservative estimates, commutative merge behavior, serde
//! round trips, and fail-closed budget accounting.

use std::collections::BTreeMap;

use arbitrary::{Arbitrary, Result as ArbResult, Unstructured};
use frankenengine_node::federation::atc_sketches::{
    compute_error_bound, BudgetTracker, CountMinSketch, MergeableSketch, SketchError,
    MAX_BUDGET_EVENTS, MAX_CMS_DEPTH,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_OPS: usize = 96;
const MAX_KEY_BYTES: usize = 64;
const MAX_WIDTH: u32 = 256;

#[derive(Debug)]
struct SketchCase {
    depth_seed: u8,
    width_seed: u16,
    alternate_seed: u8,
    bandwidth_cap: u16,
    compute_cap: u16,
    eps_seed: u8,
    delta_seed: u8,
    ops: Vec<SketchOp>,
}

impl<'a> Arbitrary<'a> for SketchCase {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self {
            depth_seed: u8::arbitrary(u)?,
            width_seed: u16::arbitrary(u)?,
            alternate_seed: u8::arbitrary(u)?,
            bandwidth_cap: u16::arbitrary(u)?,
            compute_cap: u16::arbitrary(u)?,
            eps_seed: u8::arbitrary(u)?,
            delta_seed: u8::arbitrary(u)?,
            ops: bounded_vec(u, MAX_OPS)?,
        })
    }
}

#[derive(Debug)]
enum SketchOp {
    AddLeft { key: KeySpec, count: u16 },
    AddRight { key: KeySpec, count: u16 },
    Estimate { key: KeySpec },
    ChargeBandwidth { bytes: u32 },
    ChargeCompute { ops: u32 },
    ProbeBounds { depth_seed: u8, width_seed: u16 },
}

impl<'a> Arbitrary<'a> for SketchOp {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        match u.int_in_range::<u8>(0..=5)? {
            0 => Ok(Self::AddLeft {
                key: KeySpec::arbitrary(u)?,
                count: u16::arbitrary(u)?,
            }),
            1 => Ok(Self::AddRight {
                key: KeySpec::arbitrary(u)?,
                count: u16::arbitrary(u)?,
            }),
            2 => Ok(Self::Estimate {
                key: KeySpec::arbitrary(u)?,
            }),
            3 => Ok(Self::ChargeBandwidth {
                bytes: u32::arbitrary(u)?,
            }),
            4 => Ok(Self::ChargeCompute {
                ops: u32::arbitrary(u)?,
            }),
            _ => Ok(Self::ProbeBounds {
                depth_seed: u8::arbitrary(u)?,
                width_seed: u16::arbitrary(u)?,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct KeySpec(Vec<u8>);

impl<'a> Arbitrary<'a> for KeySpec {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        let len = u.int_in_range::<usize>(0..=MAX_KEY_BYTES)?;
        Ok(Self(u.bytes(len)?.to_vec()))
    }
}

fn bounded_vec<'a, T: Arbitrary<'a>>(
    u: &mut Unstructured<'a>,
    max_len: usize,
) -> ArbResult<Vec<T>> {
    let len = u.int_in_range::<usize>(0..=max_len)?;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(T::arbitrary(u)?);
    }
    Ok(out)
}

fn depth_from(seed: u8) -> u32 {
    u32::from(seed % 8).saturating_add(1)
}

fn width_from(seed: u16) -> u32 {
    u32::from(seed % u16::try_from(MAX_WIDTH).unwrap_or(u16::MAX)).saturating_add(1)
}

fn invalid_depth_from(seed: u8) -> u32 {
    if seed % 2 == 0 {
        0
    } else {
        MAX_CMS_DEPTH.saturating_add(1)
    }
}

fn add_and_check(
    sketch: &mut CountMinSketch,
    exact: &mut BTreeMap<Vec<u8>, u64>,
    key: &KeySpec,
    count: u16,
) {
    let before = sketch.total_count();
    let increment = u64::from(count);
    sketch.add(&key.0, increment);
    let after = sketch.total_count();
    assert!(
        after >= before,
        "CountMinSketch total_count must be monotonic after add"
    );

    let tracked = exact
        .entry(key.0.clone())
        .and_modify(|value| *value = value.saturating_add(increment))
        .or_insert(increment);
    let estimate = sketch.estimate(&key.0);
    assert!(
        estimate >= *tracked,
        "CountMinSketch must not underestimate an inserted key"
    );
}

fn check_budget_charge(tracker: &mut BudgetTracker, amount: u64, is_bandwidth: bool) {
    let before = if is_bandwidth {
        tracker.bandwidth_remaining()
    } else {
        tracker.compute_remaining()
    };
    let result = if is_bandwidth {
        tracker.charge_bandwidth(amount)
    } else {
        tracker.charge_compute(amount)
    };
    let after = if is_bandwidth {
        tracker.bandwidth_remaining()
    } else {
        tracker.compute_remaining()
    };

    if amount > before {
        assert!(
            result.is_err(),
            "over-budget charge must fail closed before consuming capacity"
        );
        assert_eq!(
            after, before,
            "failed budget charge must leave remaining capacity unchanged"
        );
    } else {
        assert!(result.is_ok(), "in-budget charge must be accepted");
        assert_eq!(
            after,
            before.saturating_sub(amount),
            "accepted charge must consume exactly the requested capacity"
        );
    }
    assert!(
        tracker.events().len() <= MAX_BUDGET_EVENTS,
        "budget audit event log must stay bounded"
    );
}

fn check_error_bound(depth: u32, width: u32) {
    let bound = compute_error_bound(depth, width);
    assert!(
        bound.is_ok(),
        "valid sketch dimensions must produce an error bound"
    );
    if let Ok(bound) = bound {
        assert!(bound.eps.is_finite(), "error eps must be finite");
        assert!(bound.eps > 0.0, "error eps must be positive");
        assert!(bound.delta.is_finite(), "error delta must be finite");
        assert!(
            (0.0..=1.0).contains(&bound.delta),
            "error delta must be in (0, 1]"
        );
        assert!(
            (0.0..=100.0).contains(&bound.confidence_pct()),
            "confidence percentage must be clamped to [0, 100]"
        );
    }
}

fn check_merge_laws(left: &CountMinSketch, right: &CountMinSketch, depth: u32, width: u32) {
    let mut left_then_right = left.clone();
    let mut right_then_left = right.clone();
    let left_merge = left_then_right.merge(right);
    let right_merge = right_then_left.merge(left);
    assert!(left_merge.is_ok(), "same-dimension merge must succeed");
    assert!(right_merge.is_ok(), "same-dimension merge must succeed");
    assert_eq!(
        left_then_right, right_then_left,
        "CountMinSketch merge must be commutative"
    );

    let mut with_empty = left.clone();
    if let Ok(empty) = CountMinSketch::new(depth, width) {
        assert!(
            with_empty.merge(&empty).is_ok(),
            "merge with empty same-dimension sketch must succeed"
        );
        assert_eq!(
            with_empty, *left,
            "merging an empty sketch must leave the sketch unchanged"
        );
    }

    let mismatch_depth = if depth < MAX_CMS_DEPTH {
        depth.saturating_add(1)
    } else {
        depth.saturating_sub(1)
    };
    if let Ok(mismatched) = CountMinSketch::new(mismatch_depth, width) {
        let mut clone = left.clone();
        assert!(
            matches!(
                clone.merge(&mismatched),
                Err(SketchError::DimensionMismatch { .. })
            ),
            "different sketch dimensions must fail closed on merge"
        );
    }
}

fn check_serialization(sketch: &CountMinSketch) {
    assert!(
        sketch.serialized_size() >= 8,
        "serialized_size must include at least the dimension header"
    );
    let encoded = serde_json::to_vec(sketch);
    assert!(
        encoded.is_ok(),
        "CountMinSketch must serialize for federation transport"
    );
    if let Ok(encoded) = encoded {
        let decoded = serde_json::from_slice::<CountMinSketch>(&encoded);
        assert!(
            decoded.is_ok(),
            "serialized CountMinSketch must deserialize"
        );
        if let Ok(decoded) = decoded {
            assert_eq!(
                *sketch, decoded,
                "CountMinSketch JSON round trip must preserve counters and seeds"
            );
        }
    }
}

fn check_for_bounds(eps_seed: u8, delta_seed: u8) {
    let eps = f64::from((eps_seed % 250).saturating_add(1)) / 256.0;
    let delta = f64::from((delta_seed % 250).saturating_add(1)) / 256.0;
    let sketch = CountMinSketch::for_bounds(eps, delta);
    assert!(
        sketch.is_ok(),
        "valid eps/delta parameters must construct a bounded sketch"
    );
    if let Ok(sketch) = sketch {
        let bound = sketch.error_bound();
        assert!(bound.eps.is_finite(), "for_bounds eps must be finite");
        assert!(bound.delta.is_finite(), "for_bounds delta must be finite");
        assert!(sketch.depth() > 0, "for_bounds depth must be positive");
        assert!(sketch.width() > 0, "for_bounds width must be positive");
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut u = Unstructured::new(data);
    let Ok(case) = SketchCase::arbitrary(&mut u) else {
        return;
    };
    let depth = depth_from(case.depth_seed);
    let width = width_from(case.width_seed);
    let Ok(mut left) = CountMinSketch::new(depth, width) else {
        return;
    };
    let Ok(mut right) = CountMinSketch::new(depth, width) else {
        return;
    };
    let mut exact_left = BTreeMap::new();
    let mut exact_right = BTreeMap::new();
    let mut budget = BudgetTracker::new(u64::from(case.bandwidth_cap), u64::from(case.compute_cap));

    for op in &case.ops {
        match op {
            SketchOp::AddLeft { key, count } => {
                add_and_check(&mut left, &mut exact_left, key, *count);
            }
            SketchOp::AddRight { key, count } => {
                add_and_check(&mut right, &mut exact_right, key, *count);
            }
            SketchOp::Estimate { key } => {
                let left_estimate = left.estimate(&key.0);
                let right_estimate = right.estimate(&key.0);
                assert!(left_estimate <= left.total_count());
                assert!(right_estimate <= right.total_count());
            }
            SketchOp::ChargeBandwidth { bytes } => {
                check_budget_charge(&mut budget, u64::from(*bytes), true);
            }
            SketchOp::ChargeCompute { ops } => {
                check_budget_charge(&mut budget, u64::from(*ops), false);
            }
            SketchOp::ProbeBounds {
                depth_seed,
                width_seed,
            } => {
                check_error_bound(depth_from(*depth_seed), width_from(*width_seed));
                let invalid_depth = invalid_depth_from(*depth_seed);
                assert!(
                    matches!(
                        compute_error_bound(invalid_depth, width_from(*width_seed)),
                        Err(SketchError::InvalidDimensions { .. })
                    ),
                    "invalid dimensions must fail closed at the error-bound boundary"
                );
            }
        }
    }

    check_error_bound(depth, width);
    check_merge_laws(&left, &right, depth, width);
    check_serialization(&left);
    check_for_bounds(case.eps_seed, case.delta_seed);

    let alternate_depth = invalid_depth_from(case.alternate_seed);
    assert!(
        matches!(
            CountMinSketch::new(alternate_depth, width),
            Err(SketchError::InvalidDimensions { .. })
        ),
        "invalid CountMinSketch dimensions must be rejected"
    );
});
