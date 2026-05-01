//! Benchmark suite for measuring asupersync integration overhead on control-plane hot paths.
//!
//! Measures overhead of epoch validation, Cx propagation, and evidence emission
//! added by asupersync integration to four canonical hot paths:
//! - Lifecycle FSM transitions
//! - Health gate evaluations
//! - Rollout state persistence
//! - Fencing token validation
//!
//! Budget policy is loaded from `budget_policy.json` (never hardcoded).
//! See bd-1xwz for specification.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

/// Event codes for structured logging.
pub const PRF_001_BENCHMARK_STARTED: &str = "PRF-001";
pub const PRF_002_WITHIN_BUDGET: &str = "PRF-002";
pub const PRF_003_OVER_BUDGET: &str = "PRF-003";
pub const PRF_004_FLAMEGRAPH_CAPTURED: &str = "PRF-004";
pub const PRF_005_COLD_START: &str = "PRF-005";

/// Invariant tags.
pub const INV_PRF_BUDGET: &str = "INV-PRF-BUDGET";
pub const INV_PRF_POLICY_FILE: &str = "INV-PRF-POLICY-FILE";
pub const INV_PRF_FLAMEGRAPH: &str = "INV-PRF-FLAMEGRAPH";
pub const INV_PRF_COLD_START: &str = "INV-PRF-COLD-START";

// ── Budget Policy ────────────────────────────────────────────────

/// Machine-readable budget policy loaded from JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetPolicy {
    pub schema_version: String,
    pub description: String,
    pub bead_id: String,
    pub hot_paths: BTreeMap<String, HotPathBudget>,
    pub benchmark_config: BenchmarkConfig,
    pub event_codes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotPathBudget {
    pub label: String,
    pub p95_overhead_pct: f64,
    pub p99_overhead_pct: f64,
    pub cold_start_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkConfig {
    pub warmup_iterations: u64,
    pub measurement_iterations: u64,
    pub cold_start_iterations: u64,
}

impl BudgetPolicy {
    /// Load policy from a JSON file (INV-PRF-POLICY-FILE: never hardcoded).
    pub fn load(path: &Path) -> Result<Self, String> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read budget policy: {e}"))?;
        serde_json::from_str(&data)
            .map_err(|e| format!("failed to parse budget policy: {e}"))
    }

    pub fn budget_for(&self, hot_path: &str) -> Option<&HotPathBudget> {
        self.hot_paths.get(hot_path)
    }
}

// ── Measurement Types ────────────────────────────────────────────

/// Raw timing samples from a single benchmark run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkSamples {
    pub hot_path: String,
    pub baseline_ns: Vec<u64>,
    pub integrated_ns: Vec<u64>,
    pub cold_start_baseline_ns: Vec<u64>,
    pub cold_start_integrated_ns: Vec<u64>,
}

/// Computed statistics for a single hot path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotPathReport {
    pub hot_path: String,
    pub label: String,
    pub baseline_p50_us: f64,
    pub baseline_p95_us: f64,
    pub baseline_p99_us: f64,
    pub integrated_p50_us: f64,
    pub integrated_p95_us: f64,
    pub integrated_p99_us: f64,
    pub overhead_p95_pct: f64,
    pub overhead_p99_pct: f64,
    pub cold_start_ms: f64,
    pub within_budget: bool,
    pub budget_violations: Vec<String>,
}

/// Full benchmark report aggregating all hot paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverheadReport {
    pub bead_id: String,
    pub timestamp: String,
    pub policy_version: String,
    pub hot_paths: Vec<HotPathReport>,
    pub all_within_budget: bool,
    pub flamegraph_paths: Vec<String>,
    pub events: Vec<BenchmarkEvent>,
}

/// Structured log event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkEvent {
    pub event_code: String,
    pub hot_path: String,
    pub detail: String,
    pub trace_id: String,
}

// ── Statistics ────────────────────────────────────────────────────

/// Compute percentile from a sorted slice (linear interpolation).
pub fn percentile(sorted: &[u64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0] as f64;
    }
    let p = p.clamp(0.0, 100.0);
    let rank = p / 100.0 * (sorted.len() - 1) as f64;
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;
    let frac = rank - lower as f64;
    sorted[lower] as f64 * (1.0 - frac) + sorted[upper] as f64 * frac
}

/// Convert nanoseconds to microseconds.
pub fn ns_to_us(ns: f64) -> f64 {
    ns / 1_000.0
}

/// Convert nanoseconds to milliseconds.
pub fn ns_to_ms(ns: f64) -> f64 {
    ns / 1_000_000.0
}

/// Compute overhead percentage: (integrated - baseline) / baseline * 100.
pub fn overhead_pct(baseline: f64, integrated: f64) -> f64 {
    if baseline <= 0.0 {
        return 0.0;
    }
    (integrated - baseline) / baseline * 100.0
}

// ── Benchmark Runner ─────────────────────────────────────────────

/// Run a micro-benchmark: call `f` for `iterations` after `warmup` warmups.
/// Returns sorted nanosecond timings.
pub fn run_microbench<F: FnMut()>(mut f: F, warmup: u64, iterations: u64) -> Vec<u64> {
    // Warmup phase
    for _ in 0..warmup {
        f();
    }
    // Measurement phase
    let mut timings = Vec::with_capacity(iterations as usize);
    for _ in 0..iterations {
        let start = Instant::now();
        f();
        let elapsed = start.elapsed().as_nanos() as u64;
        timings.push(elapsed);
    }
    timings.sort();
    timings
}

/// Run cold-start measurement: call `setup` then immediately time `f`.
/// Repeated `iterations` times; each call to `setup` resets any warm caches.
pub fn run_cold_start<S: FnMut(), F: FnMut()>(
    mut setup: S,
    mut f: F,
    iterations: u64,
) -> Vec<u64> {
    let mut timings = Vec::with_capacity(iterations as usize);
    for _ in 0..iterations {
        setup();
        let start = Instant::now();
        f();
        let elapsed = start.elapsed().as_nanos() as u64;
        timings.push(elapsed);
    }
    timings.sort();
    timings
}

/// Evaluate a single hot path against its budget, producing a report row.
pub fn evaluate_hot_path(
    samples: &BenchmarkSamples,
    budget: &HotPathBudget,
    trace_id: &str,
) -> (HotPathReport, Vec<BenchmarkEvent>) {
    let mut events = Vec::new();

    events.push(BenchmarkEvent {
        event_code: PRF_001_BENCHMARK_STARTED.to_string(),
        hot_path: samples.hot_path.clone(),
        detail: format!("{} samples", samples.baseline_ns.len()),
        trace_id: trace_id.to_string(),
    });

    let bp50 = ns_to_us(percentile(&samples.baseline_ns, 50.0));
    let bp95 = ns_to_us(percentile(&samples.baseline_ns, 95.0));
    let bp99 = ns_to_us(percentile(&samples.baseline_ns, 99.0));
    let ip50 = ns_to_us(percentile(&samples.integrated_ns, 50.0));
    let ip95 = ns_to_us(percentile(&samples.integrated_ns, 95.0));
    let ip99 = ns_to_us(percentile(&samples.integrated_ns, 99.0));

    let ovh_p95 = overhead_pct(bp95, ip95);
    let ovh_p99 = overhead_pct(bp99, ip99);

    // Cold-start: use p95 of integrated cold-start samples
    let cold_ns = percentile(&samples.cold_start_integrated_ns, 95.0);
    let cold_ms = ns_to_ms(cold_ns);

    events.push(BenchmarkEvent {
        event_code: PRF_005_COLD_START.to_string(),
        hot_path: samples.hot_path.clone(),
        detail: format!("{:.3} ms", cold_ms),
        trace_id: trace_id.to_string(),
    });

    let mut violations = Vec::new();
    if ovh_p95 > budget.p95_overhead_pct {
        violations.push(format!(
            "p95 overhead {:.1}% exceeds budget {:.1}%",
            ovh_p95, budget.p95_overhead_pct
        ));
    }
    if ovh_p99 > budget.p99_overhead_pct {
        violations.push(format!(
            "p99 overhead {:.1}% exceeds budget {:.1}%",
            ovh_p99, budget.p99_overhead_pct
        ));
    }
    if cold_ms > budget.cold_start_ms {
        violations.push(format!(
            "cold-start {:.3} ms exceeds budget {:.1} ms",
            cold_ms, budget.cold_start_ms
        ));
    }

    let within_budget = violations.is_empty();

    if within_budget {
        events.push(BenchmarkEvent {
            event_code: PRF_002_WITHIN_BUDGET.to_string(),
            hot_path: samples.hot_path.clone(),
            detail: format!("p95={:.1}% p99={:.1}% cold={:.3}ms", ovh_p95, ovh_p99, cold_ms),
            trace_id: trace_id.to_string(),
        });
    } else {
        events.push(BenchmarkEvent {
            event_code: PRF_003_OVER_BUDGET.to_string(),
            hot_path: samples.hot_path.clone(),
            detail: violations.join("; "),
            trace_id: trace_id.to_string(),
        });
    }

    let report = HotPathReport {
        hot_path: samples.hot_path.clone(),
        label: budget.label.clone(),
        baseline_p50_us: bp50,
        baseline_p95_us: bp95,
        baseline_p99_us: bp99,
        integrated_p50_us: ip50,
        integrated_p95_us: ip95,
        integrated_p99_us: ip99,
        overhead_p95_pct: ovh_p95,
        overhead_p99_pct: ovh_p99,
        cold_start_ms: cold_ms,
        within_budget,
        budget_violations: violations,
    };

    (report, events)
}

/// Generate CSV content from hot path reports.
pub fn generate_csv(reports: &[HotPathReport]) -> String {
    let mut csv = String::from(
        "hot_path,baseline_p50_us,baseline_p95_us,baseline_p99_us,\
         integrated_p50_us,integrated_p95_us,integrated_p99_us,\
         overhead_p95_pct,overhead_p99_pct,cold_start_ms,within_budget\n",
    );
    for r in reports {
        csv.push_str(&format!(
            "{},{:.2},{:.2},{:.2},{:.2},{:.2},{:.2},{:.1},{:.1},{:.3},{}\n",
            r.hot_path,
            r.baseline_p50_us,
            r.baseline_p95_us,
            r.baseline_p99_us,
            r.integrated_p50_us,
            r.integrated_p95_us,
            r.integrated_p99_us,
            r.overhead_p95_pct,
            r.overhead_p99_pct,
            r.cold_start_ms,
            r.within_budget,
        ));
    }
    csv
}

/// Record a flamegraph capture event.
pub fn flamegraph_event(hot_path: &str, path: &str, trace_id: &str) -> BenchmarkEvent {
    BenchmarkEvent {
        event_code: PRF_004_FLAMEGRAPH_CAPTURED.to_string(),
        hot_path: hot_path.to_string(),
        detail: format!("captured: {path}"),
        trace_id: trace_id.to_string(),
    }
}

// ── Unit Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn policy_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("benchmarks/asupersync_integration_overhead/budget_policy.json")
    }

    // ── Policy Loading ───────────────────────────────────────────

    #[test]
    fn test_load_policy() {
        let policy = BudgetPolicy::load(&policy_path()).unwrap();
        assert_eq!(policy.schema_version, "1.0");
        assert_eq!(policy.bead_id, "bd-1xwz");
    }

    #[test]
    fn test_policy_has_four_hot_paths() {
        let policy = BudgetPolicy::load(&policy_path()).unwrap();
        assert_eq!(policy.hot_paths.len(), 4);
    }

    #[test]
    fn test_policy_lifecycle_budget() {
        let policy = BudgetPolicy::load(&policy_path()).unwrap();
        let b = policy.budget_for("lifecycle_transition").unwrap();
        assert_eq!(b.p95_overhead_pct, 25.0);
        assert_eq!(b.p99_overhead_pct, 50.0);
        assert_eq!(b.cold_start_ms, 5.0);
    }

    #[test]
    fn test_policy_health_gate_budget() {
        let policy = BudgetPolicy::load(&policy_path()).unwrap();
        let b = policy.budget_for("health_gate_eval").unwrap();
        assert_eq!(b.p95_overhead_pct, 25.0);
        assert_eq!(b.cold_start_ms, 10.0);
    }

    #[test]
    fn test_policy_rollout_budget() {
        let policy = BudgetPolicy::load(&policy_path()).unwrap();
        let b = policy.budget_for("rollout_persist").unwrap();
        assert_eq!(b.p95_overhead_pct, 15.0);
        assert_eq!(b.p99_overhead_pct, 30.0);
    }

    #[test]
    fn test_policy_fencing_budget() {
        let policy = BudgetPolicy::load(&policy_path()).unwrap();
        let b = policy.budget_for("fencing_validate").unwrap();
        assert_eq!(b.p95_overhead_pct, 20.0);
        assert_eq!(b.cold_start_ms, 5.0);
    }

    #[test]
    fn test_policy_benchmark_config() {
        let policy = BudgetPolicy::load(&policy_path()).unwrap();
        assert_eq!(policy.benchmark_config.warmup_iterations, 100);
        assert_eq!(policy.benchmark_config.measurement_iterations, 1000);
        assert_eq!(policy.benchmark_config.cold_start_iterations, 10);
    }

    #[test]
    fn test_policy_event_codes() {
        let policy = BudgetPolicy::load(&policy_path()).unwrap();
        assert_eq!(policy.event_codes.len(), 5);
        assert!(policy.event_codes.contains_key("PRF-001"));
        assert!(policy.event_codes.contains_key("PRF-005"));
    }

    #[test]
    fn test_policy_missing_file() {
        let result = BudgetPolicy::load(Path::new("/nonexistent"));
        assert!(result.is_err());
    }

    // ── Percentile Computation ───────────────────────────────────

    #[test]
    fn test_percentile_empty() {
        assert_eq!(percentile(&[], 50.0), 0.0);
    }

    #[test]
    fn test_percentile_single() {
        assert_eq!(percentile(&[1000], 50.0), 1000.0);
    }

    #[test]
    fn test_percentile_p50_even() {
        let data: Vec<u64> = (1..=100).collect();
        let p50 = percentile(&data, 50.0);
        assert!((p50 - 50.5).abs() < 0.01);
    }

    #[test]
    fn test_percentile_p95() {
        let data: Vec<u64> = (1..=100).collect();
        let p95 = percentile(&data, 95.0);
        assert!((p95 - 95.05).abs() < 0.1);
    }

    #[test]
    fn test_percentile_p99() {
        let data: Vec<u64> = (1..=1000).collect();
        let p99 = percentile(&data, 99.0);
        assert!(p99 > 989.0 && p99 < 992.0);
    }

    #[test]
    fn test_percentile_p0() {
        let data: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&data, 0.0), 1.0);
    }

    #[test]
    fn test_percentile_p100() {
        let data: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&data, 100.0), 100.0);
    }

    // ── Unit Conversion ──────────────────────────────────────────

    #[test]
    fn test_ns_to_us() {
        assert_eq!(ns_to_us(1_000.0), 1.0);
    }

    #[test]
    fn test_ns_to_ms() {
        assert_eq!(ns_to_ms(1_000_000.0), 1.0);
    }

    #[test]
    fn test_ns_to_us_fractional() {
        assert!((ns_to_us(1_500.0) - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_ns_to_ms_fractional() {
        assert!((ns_to_ms(1_500_000.0) - 1.5).abs() < f64::EPSILON);
    }

    // ── Overhead Calculation ─────────────────────────────────────

    #[test]
    fn test_overhead_zero_baseline() {
        assert_eq!(overhead_pct(0.0, 100.0), 0.0);
    }

    #[test]
    fn test_overhead_equal() {
        assert_eq!(overhead_pct(100.0, 100.0), 0.0);
    }

    #[test]
    fn test_overhead_25_pct() {
        assert!((overhead_pct(100.0, 125.0) - 25.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_overhead_100_pct() {
        assert!((overhead_pct(50.0, 100.0) - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_overhead_negative() {
        // Integrated faster than baseline (noise) → negative overhead
        assert!(overhead_pct(100.0, 90.0) < 0.0);
    }

    // ── Microbench Runner ────────────────────────────────────────

    #[test]
    fn test_run_microbench_sorted() {
        let timings = run_microbench(|| { let _ = 1 + 1; }, 10, 100);
        assert_eq!(timings.len(), 100);
        for w in timings.windows(2) {
            assert!(w[0] <= w[1]);
        }
    }

    #[test]
    fn test_run_microbench_warmup_excluded() {
        let mut count = 0u64;
        let _ = run_microbench(|| { count += 1; }, 50, 100);
        // count includes warmup + measurement
        assert_eq!(count, 150);
    }

    #[test]
    fn test_run_cold_start() {
        let mut setup_count = 0u64;
        let timings = run_cold_start(|| { setup_count += 1; }, || {}, 5);
        assert_eq!(timings.len(), 5);
        assert_eq!(setup_count, 5);
    }

    // ── Evaluate Hot Path ────────────────────────────────────────

    fn make_samples(hot_path: &str, base: u64, integrated: u64) -> BenchmarkSamples {
        BenchmarkSamples {
            hot_path: hot_path.to_string(),
            baseline_ns: (0..100).map(|i| base + i).collect(),
            integrated_ns: (0..100).map(|i| integrated + i).collect(),
            cold_start_baseline_ns: (0..10).map(|i| base * 10 + i * 100).collect(),
            cold_start_integrated_ns: (0..10).map(|i| integrated * 10 + i * 100).collect(),
        }
    }

    fn make_budget() -> HotPathBudget {
        HotPathBudget {
            label: "test path".to_string(),
            p95_overhead_pct: 25.0,
            p99_overhead_pct: 50.0,
            cold_start_ms: 5.0,
        }
    }

    #[test]
    fn test_evaluate_within_budget() {
        // 10% overhead (1000 → 1100 ns)
        let samples = make_samples("test", 1000, 1100);
        let budget = make_budget();
        let (report, _events) = evaluate_hot_path(&samples, &budget, "trace-1");
        assert!(report.within_budget);
        assert!(report.budget_violations.is_empty());
    }

    #[test]
    fn test_evaluate_over_budget_p95() {
        // 30% overhead (1000 → 1300 ns), budget is 25%
        let samples = make_samples("test", 1000, 1300);
        let budget = make_budget();
        let (report, _events) = evaluate_hot_path(&samples, &budget, "trace-1");
        assert!(!report.within_budget);
        assert!(report.budget_violations.iter().any(|v| v.contains("p95")));
    }

    #[test]
    fn test_evaluate_over_budget_p99() {
        // 60% overhead on p99 (1000 → 1600 ns), budget is 50%
        let samples = make_samples("test", 1000, 1600);
        let budget = HotPathBudget {
            p95_overhead_pct: 100.0, // p95 passes
            p99_overhead_pct: 50.0,
            ..make_budget()
        };
        let (report, _events) = evaluate_hot_path(&samples, &budget, "trace-1");
        assert!(!report.within_budget);
        assert!(report.budget_violations.iter().any(|v| v.contains("p99")));
    }

    #[test]
    fn test_evaluate_cold_start_violation() {
        // Cold start exceeds budget
        let mut samples = make_samples("test", 1000, 1100);
        // Set cold-start integrated to 10ms (10_000_000 ns)
        samples.cold_start_integrated_ns = (0..10).map(|i| 10_000_000 + i * 100).collect();
        let budget = make_budget(); // cold_start_ms: 5.0
        let (report, _events) = evaluate_hot_path(&samples, &budget, "trace-1");
        assert!(!report.within_budget);
        assert!(report.budget_violations.iter().any(|v| v.contains("cold-start")));
    }

    #[test]
    fn test_evaluate_events_start() {
        let samples = make_samples("lifecycle", 1000, 1100);
        let budget = make_budget();
        let (_report, events) = evaluate_hot_path(&samples, &budget, "trace-1");
        assert!(events.iter().any(|e| e.event_code == PRF_001_BENCHMARK_STARTED));
    }

    #[test]
    fn test_evaluate_events_within_budget() {
        let samples = make_samples("lifecycle", 1000, 1100);
        let budget = make_budget();
        let (_report, events) = evaluate_hot_path(&samples, &budget, "trace-1");
        assert!(events.iter().any(|e| e.event_code == PRF_002_WITHIN_BUDGET));
    }

    #[test]
    fn test_evaluate_events_over_budget() {
        let samples = make_samples("lifecycle", 1000, 2000);
        let budget = make_budget();
        let (_report, events) = evaluate_hot_path(&samples, &budget, "trace-1");
        assert!(events.iter().any(|e| e.event_code == PRF_003_OVER_BUDGET));
    }

    #[test]
    fn test_evaluate_events_cold_start() {
        let samples = make_samples("lifecycle", 1000, 1100);
        let budget = make_budget();
        let (_report, events) = evaluate_hot_path(&samples, &budget, "trace-1");
        assert!(events.iter().any(|e| e.event_code == PRF_005_COLD_START));
    }

    #[test]
    fn test_evaluate_trace_id_propagated() {
        let samples = make_samples("lifecycle", 1000, 1100);
        let budget = make_budget();
        let (_report, events) = evaluate_hot_path(&samples, &budget, "my-trace-42");
        assert!(events.iter().all(|e| e.trace_id == "my-trace-42"));
    }

    #[test]
    fn test_evaluate_report_fields() {
        let samples = make_samples("lifecycle", 1000, 1100);
        let budget = make_budget();
        let (report, _) = evaluate_hot_path(&samples, &budget, "t");
        assert_eq!(report.hot_path, "lifecycle");
        assert_eq!(report.label, "test path");
        assert!(report.baseline_p50_us > 0.0);
        assert!(report.integrated_p50_us > 0.0);
    }

    // ── CSV Generation ───────────────────────────────────────────

    #[test]
    fn test_generate_csv_header() {
        let csv = generate_csv(&[]);
        assert!(csv.starts_with("hot_path,"));
        assert!(csv.contains("within_budget"));
    }

    #[test]
    fn test_generate_csv_row() {
        let samples = make_samples("lifecycle", 1000, 1100);
        let budget = make_budget();
        let (report, _) = evaluate_hot_path(&samples, &budget, "t");
        let csv = generate_csv(&[report]);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2); // header + 1 row
        assert!(lines[1].starts_with("lifecycle,"));
    }

    #[test]
    fn test_generate_csv_multiple_rows() {
        let paths = ["lifecycle", "health_gate", "rollout", "fencing"];
        let reports: Vec<HotPathReport> = paths
            .iter()
            .map(|p| {
                let samples = make_samples(p, 1000, 1100);
                let budget = make_budget();
                evaluate_hot_path(&samples, &budget, "t").0
            })
            .collect();
        let csv = generate_csv(&reports);
        assert_eq!(csv.lines().count(), 5); // header + 4 rows
    }

    #[test]
    fn test_generate_csv_within_budget_field() {
        let samples = make_samples("ok", 1000, 1100);
        let budget = make_budget();
        let (report, _) = evaluate_hot_path(&samples, &budget, "t");
        let csv = generate_csv(&[report]);
        assert!(csv.contains(",true\n"));
    }

    #[test]
    fn test_generate_csv_over_budget_field() {
        let samples = make_samples("bad", 1000, 2000);
        let budget = make_budget();
        let (report, _) = evaluate_hot_path(&samples, &budget, "t");
        let csv = generate_csv(&[report]);
        assert!(csv.contains(",false\n"));
    }

    // ── Flamegraph Event ─────────────────────────────────────────

    #[test]
    fn test_flamegraph_event() {
        let ev = flamegraph_event("lifecycle", "/tmp/fg.svg", "trace-1");
        assert_eq!(ev.event_code, PRF_004_FLAMEGRAPH_CAPTURED);
        assert_eq!(ev.hot_path, "lifecycle");
        assert!(ev.detail.contains("/tmp/fg.svg"));
    }

    // ── Adversarial: Zero Budgets ────────────────────────────────

    #[test]
    fn test_adversarial_zero_budgets_all_fail() {
        let zero_budget = HotPathBudget {
            label: "zero".to_string(),
            p95_overhead_pct: 0.0,
            p99_overhead_pct: 0.0,
            cold_start_ms: 0.0,
        };
        // Any non-zero overhead fails
        let samples = make_samples("test", 1000, 1001);
        let (report, _) = evaluate_hot_path(&samples, &zero_budget, "t");
        assert!(!report.within_budget);
    }

    // ── Adversarial: Infinite Budgets ────────────────────────────

    #[test]
    fn test_adversarial_infinite_budgets_all_pass() {
        let huge_budget = HotPathBudget {
            label: "infinite".to_string(),
            p95_overhead_pct: f64::MAX,
            p99_overhead_pct: f64::MAX,
            cold_start_ms: f64::MAX,
        };
        let samples = make_samples("test", 1, 1_000_000);
        let (report, _) = evaluate_hot_path(&samples, &huge_budget, "t");
        assert!(report.within_budget);
    }

    // ── Event Code Constants ─────────────────────────────────────

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(PRF_001_BENCHMARK_STARTED, "PRF-001");
        assert_eq!(PRF_002_WITHIN_BUDGET, "PRF-002");
        assert_eq!(PRF_003_OVER_BUDGET, "PRF-003");
        assert_eq!(PRF_004_FLAMEGRAPH_CAPTURED, "PRF-004");
        assert_eq!(PRF_005_COLD_START, "PRF-005");
    }

    // ── Invariant Constants ──────────────────────────────────────

    #[test]
    fn test_invariant_constants_defined() {
        assert_eq!(INV_PRF_BUDGET, "INV-PRF-BUDGET");
        assert_eq!(INV_PRF_POLICY_FILE, "INV-PRF-POLICY-FILE");
        assert_eq!(INV_PRF_FLAMEGRAPH, "INV-PRF-FLAMEGRAPH");
        assert_eq!(INV_PRF_COLD_START, "INV-PRF-COLD-START");
    }

    // ── Serde Roundtrips ─────────────────────────────────────────

    #[test]
    fn test_hot_path_report_serde() {
        let samples = make_samples("lifecycle", 1000, 1100);
        let budget = make_budget();
        let (report, _) = evaluate_hot_path(&samples, &budget, "t");
        let json = serde_json::to_string(&report).unwrap();
        let round: HotPathReport = serde_json::from_str(&json).unwrap();
        assert_eq!(round.hot_path, "lifecycle");
        assert_eq!(round.within_budget, report.within_budget);
    }

    #[test]
    fn test_benchmark_event_serde() {
        let ev = flamegraph_event("test", "/tmp/fg.svg", "t1");
        let json = serde_json::to_string(&ev).unwrap();
        let round: BenchmarkEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(round.event_code, "PRF-004");
    }

    #[test]
    fn test_overhead_report_serde() {
        let report = OverheadReport {
            bead_id: "bd-1xwz".to_string(),
            timestamp: "2026-02-20T00:00:00Z".to_string(),
            policy_version: "1.0".to_string(),
            hot_paths: vec![],
            all_within_budget: true,
            flamegraph_paths: vec![],
            events: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        let round: OverheadReport = serde_json::from_str(&json).unwrap();
        assert_eq!(round.bead_id, "bd-1xwz");
    }

    #[test]
    fn test_budget_policy_serde() {
        let policy = BudgetPolicy::load(&policy_path()).unwrap();
        let json = serde_json::to_string(&policy).unwrap();
        let round: BudgetPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(round.hot_paths.len(), 4);
    }

    #[test]
    fn test_benchmark_samples_serde() {
        let samples = make_samples("test", 100, 200);
        let json = serde_json::to_string(&samples).unwrap();
        let round: BenchmarkSamples = serde_json::from_str(&json).unwrap();
        assert_eq!(round.baseline_ns.len(), 100);
    }
}
