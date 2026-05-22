#![no_main]

//! Fuzz harness for
//! `frankenengine_node::policy::perf_budget_guard::PerformanceBudgetGuard::evaluate`
//! at `crates/franken-node/src/policy/perf_budget_guard.rs:298`. The
//! guard is the CI gate that compares each hot-path benchmark
//! measurement against its budget policy and reports violations. A
//! regression that mishandles NaN/Inf in `cold_start_ms` or in the
//! computed `overhead_p95_pct` / `overhead_p99_pct` could let a
//! pathological measurement slip past the budget gate undetected.
//!
//! Existing fuzz coverage of this gate: **zero**.
//!
//! Five invariants pinned per call:
//!
//!   (A) **INV-PBG-PANIC-FREE** — arbitrary measurement + policy
//!       inputs MUST NOT panic the guard.
//!
//!   (B) **INV-PBG-EMPTY-REJECTED** — `evaluate(&[])` MUST return
//!       `Err(ERR_NO_MEASUREMENTS)`. Catches a regression that
//!       silently passes on empty input.
//!
//!   (C) **INV-PBG-DETERMINISM** — two consecutive `evaluate` calls
//!       on the same `(policy, measurements)` produce structurally-
//!       identical `GateResult` outputs (same path_results length,
//!       same paths_within_budget + paths_over_budget counts).
//!
//!   (D) **INV-PBG-COUNT-CONSERVATION** — for every successful
//!       evaluation: `paths_within_budget + paths_over_budget ==
//!       total_paths == path_results.len()`. Catches a regression
//!       where a measurement is double-counted or dropped from the
//!       totals.
//!
//!   (E) **INV-PBG-NAN-COUNTS-OVER-BUDGET** — any measurement with
//!       a NaN/Inf `cold_start_ms` MUST land in `over_budget`. The
//!       implementation guards against this at
//!       perf_budget_guard.rs:357-366; pinning the invariant catches
//!       a future refactor that drops the `is_finite()` check.

use arbitrary::Arbitrary;
use frankenengine_node::policy::perf_budget_guard::{
    BenchmarkMeasurement, BudgetPolicy, PathBudget, PerformanceBudgetGuard,
};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

const MAX_MEASUREMENTS: usize = 16;
const MAX_NAME_BYTES: usize = 128;
const MAX_TRACE_BYTES: usize = 64;

#[derive(Debug, Arbitrary)]
struct PerfBudgetFuzzCase {
    trace_id: String,
    measurements: Vec<RawMeasurement>,
    policy_default_p95: f64,
    policy_default_p99: f64,
    policy_default_cold_start: f64,
    custom_budgets: Vec<(String, RawBudget)>,
}

#[derive(Debug, Arbitrary)]
struct RawMeasurement {
    hot_path: String,
    baseline_p50_us: f64,
    baseline_p95_us: f64,
    baseline_p99_us: f64,
    integrated_p50_us: f64,
    integrated_p95_us: f64,
    integrated_p99_us: f64,
    cold_start_ms: f64,
}

#[derive(Debug, Arbitrary)]
struct RawBudget {
    max_overhead_p95_pct: f64,
    max_overhead_p99_pct: f64,
    max_cold_start_ms: f64,
}

fuzz_target!(|case: PerfBudgetFuzzCase| {
    let trace_id = bounded(&case.trace_id, MAX_TRACE_BYTES);
    let policy = build_policy(&case);

    // ── (B) Empty input rejection ───────────────────────────────────
    let mut empty_guard = PerformanceBudgetGuard::new(policy.clone(), &trace_id);
    let empty_result = empty_guard.evaluate(&[]);
    assert!(
        empty_result.is_err(),
        "INV-PBG-EMPTY-REJECTED violated: evaluate(&[]) returned Ok"
    );

    if case.measurements.is_empty() {
        return;
    }

    let measurements = build_measurements(&case.measurements);

    // ── (A) Panic-freedom: call itself is the assertion ─────────────
    let mut guard = PerformanceBudgetGuard::new(policy.clone(), &trace_id);
    let result = guard
        .evaluate(&measurements)
        .expect("non-empty measurements must yield Ok(GateResult)");

    // ── (D) Count conservation ─────────────────────────────────────
    let path_results_len = result.path_results.len();
    assert_eq!(
        result.total_paths, path_results_len,
        "INV-PBG-COUNT-CONSERVATION violated: total_paths={} but path_results.len()={}",
        result.total_paths, path_results_len,
    );
    assert_eq!(
        result.paths_within_budget + result.paths_over_budget,
        result.total_paths,
        "INV-PBG-COUNT-CONSERVATION violated: within({}) + over({}) != total({})",
        result.paths_within_budget,
        result.paths_over_budget,
        result.total_paths,
    );

    // ── (E) NaN/Inf cold_start_ms forces over-budget ────────────────
    for (i, m) in measurements.iter().enumerate() {
        if !m.cold_start_ms.is_finite() {
            let path_result = &result.path_results[i];
            assert!(
                !path_result.within_budget,
                "INV-PBG-NAN-COUNTS-OVER-BUDGET violated: measurement[{i}] \
                 cold_start_ms={} (non-finite) reported within_budget=true",
                m.cold_start_ms
            );
        }
    }

    // ── (C) Determinism — second call yields structurally-identical result ─
    let mut guard2 = PerformanceBudgetGuard::new(policy, &trace_id);
    let result2 = guard2
        .evaluate(&measurements)
        .expect("second eval must also succeed");
    assert_eq!(
        result.total_paths, result2.total_paths,
        "INV-PBG-DETERMINISM violated: total_paths differs ({} vs {})",
        result.total_paths, result2.total_paths,
    );
    assert_eq!(
        result.paths_within_budget, result2.paths_within_budget,
        "INV-PBG-DETERMINISM violated: paths_within_budget differs"
    );
    assert_eq!(
        result.paths_over_budget, result2.paths_over_budget,
        "INV-PBG-DETERMINISM violated: paths_over_budget differs"
    );
});

fn build_policy(case: &PerfBudgetFuzzCase) -> BudgetPolicy {
    let mut budgets: BTreeMap<String, PathBudget> = BTreeMap::new();
    for (label, raw) in case.custom_budgets.iter().take(8) {
        budgets.insert(
            bounded(label, MAX_NAME_BYTES),
            PathBudget {
                max_overhead_p95_pct: raw.max_overhead_p95_pct,
                max_overhead_p99_pct: raw.max_overhead_p99_pct,
                max_cold_start_ms: raw.max_cold_start_ms,
            },
        );
    }
    BudgetPolicy {
        budgets,
        default_budget: PathBudget {
            max_overhead_p95_pct: case.policy_default_p95,
            max_overhead_p99_pct: case.policy_default_p99,
            max_cold_start_ms: case.policy_default_cold_start,
        },
    }
}

fn build_measurements(raw: &[RawMeasurement]) -> Vec<BenchmarkMeasurement> {
    raw.iter()
        .take(MAX_MEASUREMENTS)
        .map(|r| BenchmarkMeasurement {
            hot_path: bounded(&r.hot_path, MAX_NAME_BYTES),
            baseline_p50_us: r.baseline_p50_us,
            baseline_p95_us: r.baseline_p95_us,
            baseline_p99_us: r.baseline_p99_us,
            integrated_p50_us: r.integrated_p50_us,
            integrated_p95_us: r.integrated_p95_us,
            integrated_p99_us: r.integrated_p99_us,
            cold_start_ms: r.cold_start_ms,
        })
        .collect()
}

fn bounded(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut out = String::with_capacity(max_bytes);
    for ch in s.chars() {
        if out.len().saturating_add(ch.len_utf8()) > max_bytes {
            break;
        }
        out.push(ch);
    }
    out
}
