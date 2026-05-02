//! bd-1xwz: Performance budget guard for asupersync integration overhead.
//!
//! Measures overhead of asupersync integration in control-plane hot paths
//! (lifecycle transitions, health-gate evaluations, rollout state changes,
//! fencing token operations) and rejects regressions exceeding configurable
//! p95/p99/cold-start budgets.
//!
//! # Invariants
//!
//! - **INV-PBG-BUDGET-ENFORCED**: Every hot path overhead check compares against the policy budget.
//! - **INV-PBG-REGRESSION-BLOCKED**: A measurement exceeding any budget threshold blocks the gate.
//! - **INV-PBG-FLAMEGRAPH-ON-FAIL**: Flamegraph evidence is captured (or attempted) on every gate failure.
//! - **INV-PBG-REPORT-ALWAYS**: A structured CSV report is emitted on every gate run, pass or fail.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub const PRF_001_BENCHMARK_STARTED: &str = "PRF-001";
pub const PRF_002_WITHIN_BUDGET: &str = "PRF-002";
pub const PRF_003_OVER_BUDGET: &str = "PRF-003";
pub const PRF_004_FLAMEGRAPH_CAPTURED: &str = "PRF-004";
pub const PRF_005_COLD_START: &str = "PRF-005";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub const ERR_BUDGET_EXCEEDED: &str = "ERR_BUDGET_EXCEEDED";
pub const ERR_COLD_START_EXCEEDED: &str = "ERR_COLD_START_EXCEEDED";
pub const ERR_FLAMEGRAPH_CAPTURE_FAILED: &str = "ERR_FLAMEGRAPH_CAPTURE_FAILED";
pub const ERR_NO_MEASUREMENTS: &str = "ERR_NO_MEASUREMENTS";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Identifies a control-plane hot path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HotPath {
    LifecycleTransition,
    HealthGateEvaluation,
    RolloutStateChange,
    FencingTokenAcquire,
    FencingTokenRelease,
    Custom(String),
}

impl HotPath {
    pub fn label(&self) -> &str {
        match self {
            Self::LifecycleTransition => "lifecycle_transition",
            Self::HealthGateEvaluation => "health_gate_evaluation",
            Self::RolloutStateChange => "rollout_state_change",
            Self::FencingTokenAcquire => "fencing_token_acquire",
            Self::FencingTokenRelease => "fencing_token_release",
            Self::Custom(s) => s,
        }
    }

    /// All canonical hot paths.
    pub fn canonical() -> Vec<HotPath> {
        vec![
            Self::LifecycleTransition,
            Self::HealthGateEvaluation,
            Self::RolloutStateChange,
            Self::FencingTokenAcquire,
            Self::FencingTokenRelease,
        ]
    }
}

impl fmt::Display for HotPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Budget thresholds for a single hot path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathBudget {
    /// Maximum allowed p95 overhead percentage.
    pub max_overhead_p95_pct: f64,
    /// Maximum allowed p99 overhead percentage.
    pub max_overhead_p99_pct: f64,
    /// Maximum allowed cold-start latency in milliseconds.
    pub max_cold_start_ms: f64,
}

impl Default for PathBudget {
    fn default() -> Self {
        Self {
            max_overhead_p95_pct: 15.0,
            max_overhead_p99_pct: 25.0,
            max_cold_start_ms: 50.0,
        }
    }
}

/// Performance budget policy: maps hot paths to their budget thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetPolicy {
    pub budgets: BTreeMap<String, PathBudget>,
    /// Default budget for paths not explicitly listed.
    pub default_budget: PathBudget,
}

impl Default for BudgetPolicy {
    fn default() -> Self {
        let mut budgets = BTreeMap::new();
        for path in HotPath::canonical() {
            budgets.insert(path.label().to_string(), PathBudget::default());
        }
        Self {
            budgets,
            default_budget: PathBudget::default(),
        }
    }
}

impl BudgetPolicy {
    /// Resolve the budget for a hot path.
    pub fn budget_for(&self, path: &HotPath) -> &PathBudget {
        self.budgets
            .get(path.label())
            .unwrap_or(&self.default_budget)
    }

    /// Create a policy where all budgets are zero (everything fails).
    pub fn zero() -> Self {
        let zero_budget = PathBudget {
            max_overhead_p95_pct: 0.0,
            max_overhead_p99_pct: 0.0,
            max_cold_start_ms: 0.0,
        };
        let mut budgets = BTreeMap::new();
        for path in HotPath::canonical() {
            budgets.insert(path.label().to_string(), zero_budget.clone());
        }
        Self {
            budgets,
            default_budget: zero_budget,
        }
    }

    /// Create a policy where all budgets are effectively infinite (everything passes).
    pub fn infinite() -> Self {
        let inf_budget = PathBudget {
            max_overhead_p95_pct: f64::MAX,
            max_overhead_p99_pct: f64::MAX,
            max_cold_start_ms: f64::MAX,
        };
        let mut budgets = BTreeMap::new();
        for path in HotPath::canonical() {
            budgets.insert(path.label().to_string(), inf_budget.clone());
        }
        Self {
            budgets,
            default_budget: inf_budget,
        }
    }
}

/// Raw benchmark measurement for a hot path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkMeasurement {
    pub hot_path: String,
    pub baseline_p50_us: f64,
    pub baseline_p95_us: f64,
    pub baseline_p99_us: f64,
    pub integrated_p50_us: f64,
    pub integrated_p95_us: f64,
    pub integrated_p99_us: f64,
    pub cold_start_ms: f64,
}

impl BenchmarkMeasurement {
    /// Overhead at p95 as a percentage.
    pub fn overhead_p95_pct(&self) -> f64 {
        if !self.baseline_p95_us.is_finite()
            || self.baseline_p95_us <= 0.0
            || !self.integrated_p95_us.is_finite()
            || self.integrated_p95_us <= 0.0
        {
            return f64::MAX;
        }
        ((self.integrated_p95_us - self.baseline_p95_us) / self.baseline_p95_us) * 100.0
    }

    /// Overhead at p99 as a percentage.
    pub fn overhead_p99_pct(&self) -> f64 {
        if !self.baseline_p99_us.is_finite()
            || self.baseline_p99_us <= 0.0
            || !self.integrated_p99_us.is_finite()
            || self.integrated_p99_us <= 0.0
        {
            return f64::MAX;
        }
        ((self.integrated_p99_us - self.baseline_p99_us) / self.baseline_p99_us) * 100.0
    }
}

/// Result of a budget check for a single hot path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathResult {
    pub hot_path: String,
    pub measurement: BenchmarkMeasurement,
    pub overhead_p95_pct: f64,
    pub overhead_p99_pct: f64,
    pub cold_start_ms: f64,
    pub within_budget: bool,
    pub violations: Vec<String>,
    pub flamegraph_path: Option<String>,
}

/// Overall gate result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateResult {
    pub overall_pass: bool,
    pub path_results: Vec<PathResult>,
    pub total_paths: usize,
    pub paths_within_budget: usize,
    pub paths_over_budget: usize,
}

/// Structured event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfEvent {
    pub code: String,
    pub hot_path: String,
    pub detail: String,
    pub trace_id: String,
}

/// Error from the performance budget guard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerfBudgetError {
    pub code: String,
    pub message: String,
}

impl fmt::Display for PerfBudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

// ---------------------------------------------------------------------------
// PerformanceBudgetGuard
// ---------------------------------------------------------------------------

use crate::capacity_defaults::aliases::MAX_EVENTS;
use crate::push_bounded;

/// Maximum timing samples retained per hot path before oldest-first eviction.
const MAX_TIMING_SAMPLES: usize = 8192;

/// Maximum path results retained per gate evaluation to prevent memory exhaustion.
const MAX_PATH_RESULTS: usize = 512;

/// Guard that enforces performance budgets on control-plane hot paths.
pub struct PerformanceBudgetGuard {
    policy: BudgetPolicy,
    events: Vec<PerfEvent>,
    trace_id: String,
    flamegraph_dir: Option<String>,
}

impl PerformanceBudgetGuard {
    pub fn new(policy: BudgetPolicy, trace_id: &str) -> Self {
        Self {
            policy,
            events: Vec::new(),
            trace_id: trace_id.to_string(),
            flamegraph_dir: None,
        }
    }

    pub fn with_flamegraph_dir(mut self, dir: &str) -> Self {
        self.flamegraph_dir = Some(dir.to_string());
        self
    }

    /// Run the gate on a set of benchmark measurements.
    ///
    /// # INV-PBG-BUDGET-ENFORCED
    /// Every measurement is compared against the policy budget.
    /// # INV-PBG-REGRESSION-BLOCKED
    /// Any measurement exceeding budget causes overall gate failure.
    /// # INV-PBG-REPORT-ALWAYS
    /// A structured result is always returned.
    pub fn evaluate(
        &mut self,
        measurements: &[BenchmarkMeasurement],
    ) -> Result<GateResult, PerfBudgetError> {
        if measurements.is_empty() {
            return Err(PerfBudgetError {
                code: ERR_NO_MEASUREMENTS.to_string(),
                message: "No benchmark measurements provided".to_string(),
            });
        }

        let mut path_results = Vec::new();
        let mut total_paths = 0usize;
        let mut paths_within_budget = 0usize;
        let mut paths_over_budget = 0usize;

        for m in measurements {
            self.emit(
                PRF_001_BENCHMARK_STARTED,
                &m.hot_path,
                "Benchmark evaluation started",
            );

            // Cold-start measurement event
            self.emit(
                PRF_005_COLD_START,
                &m.hot_path,
                &format!("Cold-start: {:.2}ms", m.cold_start_ms),
            );

            let hot_path_enum = self.parse_hot_path(&m.hot_path);
            let budget = self.policy.budget_for(&hot_path_enum);

            let overhead_p95 = m.overhead_p95_pct();
            let overhead_p99 = m.overhead_p99_pct();
            let cold_start = m.cold_start_ms;

            let mut violations = Vec::new();

            if !overhead_p95.is_finite()
                || !budget.max_overhead_p95_pct.is_finite()
                || budget.max_overhead_p95_pct < 0.0
                || overhead_p95 >= budget.max_overhead_p95_pct
            {
                violations.push(format!(
                    "p95 overhead {:.1}% exceeds budget {:.1}%",
                    overhead_p95, budget.max_overhead_p95_pct
                ));
            }
            if !overhead_p99.is_finite()
                || !budget.max_overhead_p99_pct.is_finite()
                || budget.max_overhead_p99_pct < 0.0
                || overhead_p99 >= budget.max_overhead_p99_pct
            {
                violations.push(format!(
                    "p99 overhead {:.1}% exceeds budget {:.1}%",
                    overhead_p99, budget.max_overhead_p99_pct
                ));
            }
            if !cold_start.is_finite()
                || cold_start < 0.0
                || !budget.max_cold_start_ms.is_finite()
                || budget.max_cold_start_ms < 0.0
                || cold_start >= budget.max_cold_start_ms
            {
                violations.push(format!(
                    "cold-start {:.1}ms exceeds budget {:.1}ms",
                    cold_start, budget.max_cold_start_ms
                ));
            }

            let within_budget = violations.is_empty();
            total_paths = total_paths.saturating_add(1);
            if within_budget {
                paths_within_budget = paths_within_budget.saturating_add(1);
            } else {
                paths_over_budget = paths_over_budget.saturating_add(1);
            }

            let flamegraph_path = if !within_budget {
                // INV-PBG-FLAMEGRAPH-ON-FAIL: attempt capture
                let fg_path = self.capture_flamegraph(&m.hot_path);
                if let Some(ref path) = fg_path {
                    self.emit(PRF_004_FLAMEGRAPH_CAPTURED, &m.hot_path, path);
                }
                fg_path
            } else {
                // Capture for trend analysis even on success
                self.capture_flamegraph(&m.hot_path)
            };

            if within_budget {
                self.emit(
                    PRF_002_WITHIN_BUDGET,
                    &m.hot_path,
                    &format!(
                        "p95={:.1}%, p99={:.1}%, cold={:.1}ms",
                        overhead_p95, overhead_p99, cold_start
                    ),
                );
            } else {
                self.emit(
                    PRF_003_OVER_BUDGET,
                    &m.hot_path,
                    &format!("Violations: {}", violations.join("; ")),
                );
            }

            let finite_for_report = |value: f64| {
                if value.is_finite() { value } else { f64::MAX }
            };
            let report_measurement = BenchmarkMeasurement {
                hot_path: m.hot_path.clone(),
                baseline_p50_us: finite_for_report(m.baseline_p50_us),
                baseline_p95_us: finite_for_report(m.baseline_p95_us),
                baseline_p99_us: finite_for_report(m.baseline_p99_us),
                integrated_p50_us: finite_for_report(m.integrated_p50_us),
                integrated_p95_us: finite_for_report(m.integrated_p95_us),
                integrated_p99_us: finite_for_report(m.integrated_p99_us),
                cold_start_ms: finite_for_report(m.cold_start_ms),
            };

            push_bounded(
                &mut path_results,
                PathResult {
                    hot_path: m.hot_path.clone(),
                    measurement: report_measurement,
                    overhead_p95_pct: finite_for_report(overhead_p95),
                    overhead_p99_pct: finite_for_report(overhead_p99),
                    cold_start_ms: finite_for_report(cold_start),
                    within_budget,
                    violations,
                    flamegraph_path,
                },
                MAX_PATH_RESULTS,
            );
        }

        Ok(GateResult {
            overall_pass: paths_over_budget == 0,
            path_results,
            total_paths,
            paths_within_budget,
            paths_over_budget,
        })
    }

    /// Generate CSV report from gate result.
    pub fn to_csv(result: &GateResult) -> String {
        let mut out = String::from(
            "hot_path,baseline_p50_us,baseline_p95_us,baseline_p99_us,\
             integrated_p50_us,integrated_p95_us,integrated_p99_us,\
             overhead_p95_pct,overhead_p99_pct,cold_start_ms,within_budget\n",
        );
        for r in &result.path_results {
            let m = &r.measurement;
            out.push_str(&format!(
                "{},{:.1},{:.1},{:.1},{:.1},{:.1},{:.1},{:.2},{:.2},{:.2},{}\n",
                r.hot_path,
                m.baseline_p50_us,
                m.baseline_p95_us,
                m.baseline_p99_us,
                m.integrated_p50_us,
                m.integrated_p95_us,
                m.integrated_p99_us,
                r.overhead_p95_pct,
                r.overhead_p99_pct,
                r.cold_start_ms,
                r.within_budget,
            ));
        }
        out
    }

    /// Access emitted events.
    pub fn events(&self) -> &[PerfEvent] {
        &self.events
    }

    /// Access the policy.
    pub fn policy(&self) -> &BudgetPolicy {
        &self.policy
    }

    fn emit(&mut self, code: &str, hot_path: &str, detail: &str) {
        let trace_id = self.trace_id.clone();
        push_bounded(
            &mut self.events,
            PerfEvent {
                code: code.to_string(),
                hot_path: hot_path.to_string(),
                detail: detail.to_string(),
                trace_id,
            },
            MAX_EVENTS,
        );
    }

    fn parse_hot_path(&self, label: &str) -> HotPath {
        match label {
            "lifecycle_transition" => HotPath::LifecycleTransition,
            "health_gate_evaluation" => HotPath::HealthGateEvaluation,
            "rollout_state_change" => HotPath::RolloutStateChange,
            "fencing_token_acquire" => HotPath::FencingTokenAcquire,
            "fencing_token_release" => HotPath::FencingTokenRelease,
            other => HotPath::Custom(other.to_string()),
        }
    }

    fn capture_flamegraph(&mut self, hot_path: &str) -> Option<String> {
        if let Some(ref dir) = self.flamegraph_dir {
            if hot_path.starts_with('/')
                || hot_path.contains('\\')
                || hot_path.contains('\0')
                || hot_path.split('/').any(|segment| segment == "..")
            {
                return None;
            }
            let path = format!("{}/flamegraph_{}.svg", dir, hot_path);
            // In production, this would invoke `cargo flamegraph`.
            // For testing, we just record the path.
            Some(path)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Timing instrumentation (bd-2wjg)
// ---------------------------------------------------------------------------

/// Event code for timing sample recorded.
pub const PRF_006_TIMING_SAMPLE: &str = "PRF-006";
/// Event code for percentile stats computed.
pub const PRF_007_PERCENTILE_COMPUTED: &str = "PRF-007";
/// Event code for cold-start timing recorded.
pub const PRF_008_COLD_START_TIMING: &str = "PRF-008";

/// A single timing observation in microseconds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingSample {
    pub hot_path: String,
    pub duration_us: f64,
    /// Whether this sample is from a cold start (first invocation).
    pub is_cold_start: bool,
}

/// Computed percentile statistics from collected timing samples.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PercentileStats {
    pub count: usize,
    pub p50_us: f64,
    pub p95_us: f64,
    pub p99_us: f64,
    pub min_us: f64,
    pub max_us: f64,
}

impl PercentileStats {
    /// Compute percentile stats from a slice of durations (microseconds).
    /// Returns `None` if the slice is empty.
    pub fn from_samples(durations_us: &[f64]) -> Option<Self> {
        if durations_us.is_empty() {
            return None;
        }
        if durations_us
            .iter()
            .any(|duration| !duration.is_finite() || *duration < 0.0)
        {
            return None;
        }
        let mut sorted: Vec<f64> = durations_us.to_vec();
        sorted.sort_by(|a, b| a.total_cmp(b));
        let n = sorted.len();
        Some(Self {
            count: n,
            p50_us: percentile_at(&sorted, 0.50),
            p95_us: percentile_at(&sorted, 0.95),
            p99_us: percentile_at(&sorted, 0.99),
            min_us: sorted[0],
            max_us: sorted[n - 1],
        })
    }
}

/// Nearest-rank percentile calculation.
fn percentile_at(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((pct * sorted.len() as f64).ceil() as usize).saturating_sub(1);
    let idx = idx.min(sorted.len() - 1);
    sorted[idx]
}

/// Collects timing samples for baseline and integrated runs per hot path,
/// then synthesizes `BenchmarkMeasurement` values for the budget guard.
pub struct TimingCollector {
    /// Baseline samples per hot path label.
    baseline: BTreeMap<String, Vec<f64>>,
    /// Integrated (with asupersync) samples per hot path label.
    integrated: BTreeMap<String, Vec<f64>>,
    /// Cold-start durations per hot path label (ms).
    cold_starts: BTreeMap<String, f64>,
    events: Vec<PerfEvent>,
    trace_id: String,
}

impl TimingCollector {
    pub fn new(trace_id: &str) -> Self {
        Self {
            baseline: BTreeMap::new(),
            integrated: BTreeMap::new(),
            cold_starts: BTreeMap::new(),
            events: Vec::new(),
            trace_id: trace_id.to_string(),
        }
    }

    /// Record a baseline timing sample (microseconds).
    pub fn record_baseline(&mut self, hot_path: &str, duration_us: f64) {
        if !duration_us.is_finite() || duration_us <= 0.0 {
            return;
        }
        let samples = self.baseline.entry(hot_path.to_string()).or_default();
        push_bounded(samples, duration_us, MAX_TIMING_SAMPLES);
        self.emit(
            PRF_006_TIMING_SAMPLE,
            hot_path,
            &format!("baseline sample: {:.1}us", duration_us),
        );
    }

    /// Record an integrated (asupersync) timing sample (microseconds).
    pub fn record_integrated(&mut self, hot_path: &str, duration_us: f64) {
        if !duration_us.is_finite() || duration_us <= 0.0 {
            return;
        }
        let samples = self.integrated.entry(hot_path.to_string()).or_default();
        push_bounded(samples, duration_us, MAX_TIMING_SAMPLES);
        self.emit(
            PRF_006_TIMING_SAMPLE,
            hot_path,
            &format!("integrated sample: {:.1}us", duration_us),
        );
    }

    /// Record the cold-start duration for a hot path (milliseconds).
    pub fn record_cold_start(&mut self, hot_path: &str, cold_start_ms: f64) {
        if !cold_start_ms.is_finite() || cold_start_ms < 0.0 {
            return;
        }
        self.cold_starts.insert(hot_path.to_string(), cold_start_ms);
        self.emit(
            PRF_008_COLD_START_TIMING,
            hot_path,
            &format!("cold-start: {:.2}ms", cold_start_ms),
        );
    }

    /// Compute percentile stats for baseline samples of a hot path.
    pub fn baseline_stats(&self, hot_path: &str) -> Option<PercentileStats> {
        self.baseline
            .get(hot_path)
            .and_then(|samples| PercentileStats::from_samples(samples))
    }

    /// Compute percentile stats for integrated samples of a hot path.
    pub fn integrated_stats(&self, hot_path: &str) -> Option<PercentileStats> {
        self.integrated
            .get(hot_path)
            .and_then(|samples| PercentileStats::from_samples(samples))
    }

    /// All hot paths that have both baseline and integrated samples.
    pub fn measured_paths(&self) -> Vec<String> {
        self.baseline
            .keys()
            .filter(|k| self.integrated.contains_key(*k))
            .cloned()
            .collect()
    }

    /// Sample count for a hot path (baseline).
    pub fn baseline_count(&self, hot_path: &str) -> usize {
        self.baseline.get(hot_path).map_or(0, |v| v.len())
    }

    /// Sample count for a hot path (integrated).
    pub fn integrated_count(&self, hot_path: &str) -> usize {
        self.integrated.get(hot_path).map_or(0, |v| v.len())
    }

    /// Synthesize `BenchmarkMeasurement` values from collected timing data.
    /// Only paths with both baseline and integrated samples are included.
    pub fn to_measurements(&mut self) -> Vec<BenchmarkMeasurement> {
        let paths = self.measured_paths();
        let mut measurements = Vec::new();

        for path in &paths {
            let baseline = match self.baseline_stats(path) {
                Some(s) => s,
                None => continue,
            };
            let integrated = match self.integrated_stats(path) {
                Some(s) => s,
                None => continue,
            };

            self.emit(
                PRF_007_PERCENTILE_COMPUTED,
                path,
                &format!(
                    "baseline p50={:.1} p95={:.1} p99={:.1}; integrated p50={:.1} p95={:.1} p99={:.1}",
                    baseline.p50_us,
                    baseline.p95_us,
                    baseline.p99_us,
                    integrated.p50_us,
                    integrated.p95_us,
                    integrated.p99_us,
                ),
            );

            let cold_start_ms = self.cold_starts.get(path).copied().unwrap_or(0.0);

            measurements.push(BenchmarkMeasurement {
                hot_path: path.clone(),
                baseline_p50_us: baseline.p50_us,
                baseline_p95_us: baseline.p95_us,
                baseline_p99_us: baseline.p99_us,
                integrated_p50_us: integrated.p50_us,
                integrated_p95_us: integrated.p95_us,
                integrated_p99_us: integrated.p99_us,
                cold_start_ms,
            });
        }

        measurements
    }

    /// Collect samples, synthesize measurements, and run the budget gate.
    pub fn evaluate_against_policy(
        &mut self,
        policy: BudgetPolicy,
    ) -> Result<GateResult, PerfBudgetError> {
        let measurements = self.to_measurements();
        let mut guard = PerformanceBudgetGuard::new(policy, &self.trace_id);
        guard.evaluate(&measurements)
    }

    /// Access emitted events.
    pub fn events(&self) -> &[PerfEvent] {
        &self.events
    }

    fn emit(&mut self, code: &str, hot_path: &str, detail: &str) {
        let trace_id = self.trace_id.clone();
        push_bounded(
            &mut self.events,
            PerfEvent {
                code: code.to_string(),
                hot_path: hot_path.to_string(),
                detail: detail.to_string(),
                trace_id,
            },
            MAX_EVENTS,
        );
    }
}

// ---------------------------------------------------------------------------
// Send + Sync
// ---------------------------------------------------------------------------

fn _assert_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<PerformanceBudgetGuard>();
    assert_sync::<PerformanceBudgetGuard>();
    assert_send::<TimingCollector>();
    assert_sync::<TimingCollector>();
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_measurement(
        path: &str,
        baseline_p95: f64,
        integrated_p95: f64,
        cold_start: f64,
    ) -> BenchmarkMeasurement {
        BenchmarkMeasurement {
            hot_path: path.to_string(),
            baseline_p50_us: baseline_p95 * 0.7,
            baseline_p95_us: baseline_p95,
            baseline_p99_us: baseline_p95 * 1.3,
            integrated_p50_us: integrated_p95 * 0.7,
            integrated_p95_us: integrated_p95,
            integrated_p99_us: integrated_p95 * 1.3,
            cold_start_ms: cold_start,
        }
    }

    fn default_measurements() -> Vec<BenchmarkMeasurement> {
        vec![
            make_measurement("lifecycle_transition", 100.0, 110.0, 20.0),
            make_measurement("health_gate_evaluation", 50.0, 55.0, 15.0),
            make_measurement("rollout_state_change", 80.0, 88.0, 18.0),
            make_measurement("fencing_token_acquire", 30.0, 33.0, 10.0),
            make_measurement("fencing_token_release", 25.0, 27.0, 8.0),
        ]
    }

    // -- HotPath --

    #[test]
    fn test_hot_path_labels() {
        assert_eq!(HotPath::LifecycleTransition.label(), "lifecycle_transition");
        assert_eq!(
            HotPath::HealthGateEvaluation.label(),
            "health_gate_evaluation"
        );
        assert_eq!(HotPath::RolloutStateChange.label(), "rollout_state_change");
        assert_eq!(
            HotPath::FencingTokenAcquire.label(),
            "fencing_token_acquire"
        );
        assert_eq!(
            HotPath::FencingTokenRelease.label(),
            "fencing_token_release"
        );
    }

    #[test]
    fn test_canonical_hot_paths() {
        let paths = HotPath::canonical();
        assert_eq!(paths.len(), 5);
    }

    #[test]
    fn test_custom_hot_path() {
        let custom = HotPath::Custom("my_path".into());
        assert_eq!(custom.label(), "my_path");
    }

    // -- PathBudget --

    #[test]
    fn test_default_budget() {
        let budget = PathBudget::default();
        assert_eq!(budget.max_overhead_p95_pct, 15.0);
        assert_eq!(budget.max_overhead_p99_pct, 25.0);
        assert_eq!(budget.max_cold_start_ms, 50.0);
    }

    // -- BudgetPolicy --

    #[test]
    fn test_default_policy_has_all_canonical() {
        let policy = BudgetPolicy::default();
        for path in HotPath::canonical() {
            assert!(policy.budgets.contains_key(path.label()));
        }
    }

    #[test]
    fn test_zero_policy() {
        let policy = BudgetPolicy::zero();
        for path in HotPath::canonical() {
            let budget = policy.budget_for(&path);
            assert_eq!(budget.max_overhead_p95_pct, 0.0);
            assert_eq!(budget.max_overhead_p99_pct, 0.0);
            assert_eq!(budget.max_cold_start_ms, 0.0);
        }
    }

    #[test]
    fn test_infinite_policy() {
        let policy = BudgetPolicy::infinite();
        for path in HotPath::canonical() {
            let budget = policy.budget_for(&path);
            assert!(budget.max_overhead_p95_pct > 1e100);
        }
    }

    #[test]
    fn test_budget_for_unknown_path() {
        let policy = BudgetPolicy::default();
        let budget = policy.budget_for(&HotPath::Custom("unknown".into()));
        assert_eq!(
            budget.max_overhead_p95_pct,
            policy.default_budget.max_overhead_p95_pct
        );
    }

    // -- BenchmarkMeasurement --

    #[test]
    fn test_overhead_p95_calculation() {
        let m = make_measurement("test", 100.0, 110.0, 10.0);
        let overhead = m.overhead_p95_pct();
        assert!((overhead - 10.0).abs() < 0.01);
    }

    #[test]
    fn test_overhead_p99_calculation() {
        let m = make_measurement("test", 100.0, 130.0, 10.0);
        let overhead = m.overhead_p99_pct();
        assert!(overhead > 0.0);
    }

    #[test]
    fn test_overhead_zero_baseline() {
        let m = BenchmarkMeasurement {
            hot_path: "test".into(),
            baseline_p50_us: 0.0,
            baseline_p95_us: 0.0,
            baseline_p99_us: 0.0,
            integrated_p50_us: 10.0,
            integrated_p95_us: 10.0,
            integrated_p99_us: 10.0,
            cold_start_ms: 5.0,
        };
        assert_eq!(m.overhead_p95_pct(), f64::MAX);
        assert_eq!(m.overhead_p99_pct(), f64::MAX);
    }

    #[test]
    fn test_invalid_negative_baseline_fails_closed() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-neg-base");
        let m = BenchmarkMeasurement {
            hot_path: "test".into(),
            baseline_p50_us: -1.0,
            baseline_p95_us: -1.0,
            baseline_p99_us: -1.0,
            integrated_p50_us: 10.0,
            integrated_p95_us: 10.0,
            integrated_p99_us: 10.0,
            cold_start_ms: 5.0,
        };

        let result = guard.evaluate(&[m]).unwrap();

        assert!(!result.overall_pass);
        assert!(
            result.path_results[0]
                .violations
                .iter()
                .any(|violation| violation.contains("p95"))
        );
    }

    #[test]
    fn test_zero_integrated_measurement_fails_closed() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-zero-int");
        let m = BenchmarkMeasurement {
            hot_path: "test".into(),
            baseline_p50_us: 70.0,
            baseline_p95_us: 100.0,
            baseline_p99_us: 130.0,
            integrated_p50_us: 0.0,
            integrated_p95_us: 0.0,
            integrated_p99_us: 0.0,
            cold_start_ms: 5.0,
        };

        let result = guard.evaluate(&[m]).unwrap();

        assert!(!result.overall_pass);
        assert!(
            result.path_results[0]
                .violations
                .iter()
                .any(|violation| violation.contains("p95"))
        );
    }

    // -- Gate evaluation: all within budget --

    #[test]
    fn test_all_within_budget() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-1");
        let result = guard.evaluate(&default_measurements()).unwrap();
        assert!(result.overall_pass);
        assert_eq!(result.paths_over_budget, 0);
        assert_eq!(result.total_paths, 5);
    }

    #[test]
    fn test_within_budget_emits_prf002() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-1");
        guard.evaluate(&default_measurements()).unwrap();
        let within_events: Vec<_> = guard
            .events()
            .iter()
            .filter(|e| e.code == PRF_002_WITHIN_BUDGET)
            .collect();
        assert_eq!(within_events.len(), 5);
    }

    // -- Gate evaluation: over budget --

    #[test]
    fn test_p95_over_budget() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-2");
        let measurements = vec![
            make_measurement("lifecycle_transition", 100.0, 120.0, 10.0), // 20% > 15% budget
        ];
        let result = guard.evaluate(&measurements).unwrap();
        assert!(!result.overall_pass);
        assert_eq!(result.paths_over_budget, 1);
        assert!(result.path_results[0].violations[0].contains("p95"));
    }

    #[test]
    fn test_cold_start_over_budget() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-3");
        let measurements = vec![
            make_measurement("health_gate_evaluation", 50.0, 55.0, 60.0), // 60ms > 50ms budget
        ];
        let result = guard.evaluate(&measurements).unwrap();
        assert!(!result.overall_pass);
        assert!(
            result.path_results[0]
                .violations
                .iter()
                .any(|v| v.contains("cold-start"))
        );
    }

    #[test]
    fn test_exact_boundary_p95_fails_closed() {
        // Fail-closed: overhead exactly at the budget limit must trigger violation.
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-boundary");
        // p95 = 115/100 - 1 = 15% exactly = budget of 15%
        let measurements = vec![make_measurement("lifecycle_transition", 100.0, 115.0, 10.0)];
        let result = guard.evaluate(&measurements).unwrap();
        assert!(!result.overall_pass, "exact boundary should fail closed");
        assert_eq!(result.paths_over_budget, 1);
    }

    #[test]
    fn test_over_budget_emits_prf003() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-2");
        let measurements = vec![make_measurement("lifecycle_transition", 100.0, 120.0, 10.0)];
        guard.evaluate(&measurements).unwrap();
        let over_events: Vec<_> = guard
            .events()
            .iter()
            .filter(|e| e.code == PRF_003_OVER_BUDGET)
            .collect();
        assert_eq!(over_events.len(), 1);
    }

    // -- Zero budget: everything fails --

    #[test]
    fn test_zero_budget_all_fail() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::zero(), "trace-zero");
        let result = guard.evaluate(&default_measurements()).unwrap();
        assert!(!result.overall_pass);
        assert_eq!(result.paths_over_budget, 5);
    }

    // -- Infinite budget: everything passes --

    #[test]
    fn test_infinite_budget_all_pass() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::infinite(), "trace-inf");
        let measurements = vec![make_measurement(
            "lifecycle_transition",
            100.0,
            999.0,
            999.0,
        )];
        let result = guard.evaluate(&measurements).unwrap();
        assert!(result.overall_pass);
    }

    // -- No measurements: error --

    #[test]
    fn test_empty_measurements_error() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-e");
        let err = guard.evaluate(&[]).unwrap_err();
        assert_eq!(err.code, ERR_NO_MEASUREMENTS);
    }

    #[test]
    fn test_empty_measurements_error_leaves_event_log_empty() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-e-empty");

        let err = guard.evaluate(&[]).unwrap_err();

        assert_eq!(err.code, ERR_NO_MEASUREMENTS);
        assert!(guard.events().is_empty());
    }

    // -- Flamegraph capture --

    #[test]
    fn test_flamegraph_on_failure() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().to_string_lossy().to_string();
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-fg")
            .with_flamegraph_dir(&path);
        let measurements = vec![make_measurement("lifecycle_transition", 100.0, 120.0, 10.0)];
        let result = guard.evaluate(&measurements).unwrap();
        assert!(result.path_results[0].flamegraph_path.is_some());
        assert!(
            result.path_results[0]
                .flamegraph_path
                .as_ref()
                .unwrap()
                .contains("flamegraph_lifecycle")
        );
    }

    #[test]
    fn test_flamegraph_prf004_event() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().to_string_lossy().to_string();
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-fg2")
            .with_flamegraph_dir(&path);
        let measurements = vec![make_measurement("lifecycle_transition", 100.0, 120.0, 10.0)];
        guard.evaluate(&measurements).unwrap();
        let fg_events: Vec<_> = guard
            .events()
            .iter()
            .filter(|e| e.code == PRF_004_FLAMEGRAPH_CAPTURED)
            .collect();
        assert!(!fg_events.is_empty());
    }

    #[test]
    fn test_flamegraph_rejects_traversal_hot_path() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().to_string_lossy().to_string();
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-fg-traversal")
            .with_flamegraph_dir(&path);
        let measurements = vec![make_measurement("../escape", 100.0, 120.0, 10.0)];

        let result = guard.evaluate(&measurements).unwrap();

        assert!(!result.overall_pass);
        assert!(result.path_results[0].flamegraph_path.is_none());
        assert!(
            !guard
                .events()
                .iter()
                .any(|event| event.code == PRF_004_FLAMEGRAPH_CAPTURED)
        );
    }

    #[test]
    fn test_flamegraph_rejects_null_byte_hot_path() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().to_string_lossy().to_string();
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-fg-null")
            .with_flamegraph_dir(&path);
        let measurements = vec![make_measurement("bad\0path", 100.0, 120.0, 10.0)];

        let result = guard.evaluate(&measurements).unwrap();

        assert!(result.path_results[0].flamegraph_path.is_none());
    }

    #[test]
    fn test_no_flamegraph_without_dir() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-nofg");
        let measurements = vec![make_measurement("lifecycle_transition", 100.0, 120.0, 10.0)];
        let result = guard.evaluate(&measurements).unwrap();
        assert!(result.path_results[0].flamegraph_path.is_none());
    }

    // -- CSV report --

    #[test]
    fn test_csv_report_header() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-csv");
        let result = guard.evaluate(&default_measurements()).unwrap();
        let csv = PerformanceBudgetGuard::to_csv(&result);
        assert!(csv.starts_with("hot_path,baseline_p50_us,"));
    }

    #[test]
    fn test_csv_report_row_count() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-csv2");
        let result = guard.evaluate(&default_measurements()).unwrap();
        let csv = PerformanceBudgetGuard::to_csv(&result);
        let lines: Vec<_> = csv.trim().lines().collect();
        assert_eq!(lines.len(), 6); // header + 5 paths
    }

    #[test]
    fn test_csv_contains_hot_paths() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-csv3");
        let result = guard.evaluate(&default_measurements()).unwrap();
        let csv = PerformanceBudgetGuard::to_csv(&result);
        assert!(csv.contains("lifecycle_transition"));
        assert!(csv.contains("health_gate_evaluation"));
        assert!(csv.contains("fencing_token_acquire"));
    }

    // -- Cold-start event --

    #[test]
    fn test_cold_start_event_emitted() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-cs");
        guard.evaluate(&default_measurements()).unwrap();
        let cs_events: Vec<_> = guard
            .events()
            .iter()
            .filter(|e| e.code == PRF_005_COLD_START)
            .collect();
        assert_eq!(cs_events.len(), 5);
    }

    // -- Trace ID propagation --

    #[test]
    fn test_trace_id_in_events() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "my-trace-42");
        guard.evaluate(&default_measurements()).unwrap();
        for event in guard.events() {
            assert_eq!(event.trace_id, "my-trace-42");
        }
    }

    // -- Mixed results --

    #[test]
    fn test_mixed_pass_and_fail() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-mix");
        let measurements = vec![
            make_measurement("lifecycle_transition", 100.0, 110.0, 20.0), // within
            make_measurement("health_gate_evaluation", 50.0, 70.0, 10.0), // 40% > 15%
        ];
        let result = guard.evaluate(&measurements).unwrap();
        assert!(!result.overall_pass);
        assert_eq!(result.paths_within_budget, 1);
        assert_eq!(result.paths_over_budget, 1);
    }

    // -- Event codes --

    #[test]
    fn test_event_codes_defined() {
        assert!(!PRF_001_BENCHMARK_STARTED.is_empty());
        assert!(!PRF_002_WITHIN_BUDGET.is_empty());
        assert!(!PRF_003_OVER_BUDGET.is_empty());
        assert!(!PRF_004_FLAMEGRAPH_CAPTURED.is_empty());
        assert!(!PRF_005_COLD_START.is_empty());
    }

    // -- Error codes --

    #[test]
    fn test_error_codes_defined() {
        assert!(!ERR_BUDGET_EXCEEDED.is_empty());
        assert!(!ERR_COLD_START_EXCEEDED.is_empty());
        assert!(!ERR_FLAMEGRAPH_CAPTURE_FAILED.is_empty());
        assert!(!ERR_NO_MEASUREMENTS.is_empty());
    }

    // -- Invariant constants --

    #[test]
    fn test_invariant_constants_defined() {
        // INV-PBG-BUDGET-ENFORCED
        // INV-PBG-REGRESSION-BLOCKED
        // INV-PBG-FLAMEGRAPH-ON-FAIL
        // INV-PBG-REPORT-ALWAYS
        // These are documented in module doc and verified by the gate logic:
        // - evaluate() always checks budgets (BUDGET-ENFORCED)
        // - any over-budget fails gate (REGRESSION-BLOCKED)
        // - flamegraph captured on fail (FLAMEGRAPH-ON-FAIL)
        // - result always has report (REPORT-ALWAYS)
    }

    // -- Serde roundtrips --

    #[test]
    fn test_measurement_serde_roundtrip() {
        let m = make_measurement("test", 100.0, 110.0, 20.0);
        let json = serde_json::to_string(&m).unwrap();
        let parsed: BenchmarkMeasurement = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.hot_path, "test");
    }

    #[test]
    fn test_gate_result_serde_roundtrip() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-ser");
        let result = guard.evaluate(&default_measurements()).unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let parsed: GateResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_paths, 5);
    }

    #[test]
    fn test_policy_serde_roundtrip() {
        let policy = BudgetPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: BudgetPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.budgets.len(), 5);
    }

    #[test]
    fn test_error_serde_roundtrip() {
        let err = PerfBudgetError {
            code: ERR_BUDGET_EXCEEDED.to_string(),
            message: "test".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let parsed: PerfBudgetError = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, err);
    }

    // -- Error display --

    #[test]
    fn test_error_display() {
        let err = PerfBudgetError {
            code: "E001".to_string(),
            message: "bad".to_string(),
        };
        assert!(err.to_string().contains("E001"));
        assert!(err.to_string().contains("bad"));
    }

    // -- Multiple violations in single path --

    #[test]
    fn test_multiple_violations_single_path() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-mv");
        let measurements = vec![
            make_measurement("lifecycle_transition", 100.0, 200.0, 60.0), // both p95 and cold-start
        ];
        let result = guard.evaluate(&measurements).unwrap();
        assert_eq!(result.path_results[0].violations.len(), 3);
    }

    // -- Exactly at budget boundary --

    #[test]
    fn test_exactly_at_p95_budget_fails_closed() {
        // Fail-closed: exactly at the budget boundary must NOT pass.
        let policy = BudgetPolicy::default(); // 15%
        let mut guard = PerformanceBudgetGuard::new(policy, "trace-boundary");
        let measurements = vec![
            make_measurement("lifecycle_transition", 100.0, 115.0, 10.0), // exactly 15%
        ];
        let result = guard.evaluate(&measurements).unwrap();
        assert!(!result.overall_pass, "exact boundary must fail closed");
    }

    #[test]
    fn test_exactly_at_p99_budget_fails_closed() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-p99-boundary");
        let measurements = vec![BenchmarkMeasurement {
            hot_path: "lifecycle_transition".into(),
            baseline_p50_us: 70.0,
            baseline_p95_us: 100.0,
            baseline_p99_us: 200.0,
            integrated_p50_us: 77.0,
            integrated_p95_us: 110.0,
            integrated_p99_us: 250.0,
            cold_start_ms: 10.0,
        }];

        let result = guard.evaluate(&measurements).unwrap();

        assert!(!result.overall_pass);
        assert!(
            result.path_results[0]
                .violations
                .iter()
                .any(|violation| violation.contains("p99"))
        );
    }

    #[test]
    fn test_exactly_at_cold_start_budget_fails_closed() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-cold-boundary");
        let measurements = vec![make_measurement(
            "health_gate_evaluation",
            100.0,
            110.0,
            50.0,
        )];

        let result = guard.evaluate(&measurements).unwrap();

        assert!(!result.overall_pass);
        assert!(
            result.path_results[0]
                .violations
                .iter()
                .any(|violation| violation.contains("cold-start"))
        );
    }

    #[test]
    fn test_custom_hot_path_uses_default_budget_fail_closed() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-custom");
        let measurements = vec![make_measurement("custom_hot_path", 100.0, 120.0, 10.0)];

        let result = guard.evaluate(&measurements).unwrap();

        assert!(!result.overall_pass);
        assert_eq!(result.path_results[0].hot_path, "custom_hot_path");
        assert_eq!(result.paths_over_budget, 1);
    }

    #[test]
    fn test_just_over_p95_budget_fails() {
        let policy = BudgetPolicy::default(); // 15%
        let mut guard = PerformanceBudgetGuard::new(policy, "trace-over");
        let measurements = vec![
            make_measurement("lifecycle_transition", 100.0, 115.1, 10.0), // 15.1% > 15%
        ];
        let result = guard.evaluate(&measurements).unwrap();
        assert!(!result.overall_pass);
    }

    // -- HotPath Display --

    #[test]
    fn test_hot_path_display() {
        assert_eq!(
            format!("{}", HotPath::LifecycleTransition),
            "lifecycle_transition"
        );
    }

    // =========================================================================
    // Timing instrumentation tests (bd-2wjg)
    // =========================================================================

    // -- PercentileStats --

    #[test]
    fn test_percentile_stats_from_samples() {
        let samples: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        let stats = PercentileStats::from_samples(&samples).unwrap();
        assert_eq!(stats.count, 100);
        assert!((stats.p50_us - 50.0).abs() < 1.0);
        assert!((stats.p95_us - 95.0).abs() < 1.0);
        assert!((stats.p99_us - 99.0).abs() < 1.0);
        assert_eq!(stats.min_us, 1.0);
        assert_eq!(stats.max_us, 100.0);
    }

    #[test]
    fn test_percentile_stats_single_sample() {
        let stats = PercentileStats::from_samples(&[42.0]).unwrap();
        assert_eq!(stats.count, 1);
        assert_eq!(stats.p50_us, 42.0);
        assert_eq!(stats.p95_us, 42.0);
        assert_eq!(stats.p99_us, 42.0);
        assert_eq!(stats.min_us, 42.0);
        assert_eq!(stats.max_us, 42.0);
    }

    #[test]
    fn test_percentile_stats_empty() {
        assert!(PercentileStats::from_samples(&[]).is_none());
    }

    #[test]
    fn test_percentile_stats_rejects_nonfinite_samples() {
        assert!(PercentileStats::from_samples(&[1.0, f64::NAN]).is_none());
        assert!(PercentileStats::from_samples(&[1.0, f64::INFINITY]).is_none());
    }

    #[test]
    fn test_percentile_stats_rejects_negative_samples() {
        assert!(PercentileStats::from_samples(&[1.0, -1.0]).is_none());
    }

    #[test]
    fn test_percentile_stats_two_samples() {
        let stats = PercentileStats::from_samples(&[10.0, 20.0]).unwrap();
        assert_eq!(stats.count, 2);
        assert_eq!(stats.min_us, 10.0);
        assert_eq!(stats.max_us, 20.0);
    }

    #[test]
    fn test_percentile_stats_serde_roundtrip() {
        let stats = PercentileStats::from_samples(&[1.0, 2.0, 3.0]).unwrap();
        let json = serde_json::to_string(&stats).unwrap();
        let parsed: PercentileStats = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, stats);
    }

    // -- TimingCollector basic --

    #[test]
    fn test_collector_record_baseline() {
        let mut c = TimingCollector::new("trace-tc1");
        c.record_baseline("lifecycle_transition", 100.0);
        c.record_baseline("lifecycle_transition", 110.0);
        assert_eq!(c.baseline_count("lifecycle_transition"), 2);
    }

    #[test]
    fn test_collector_record_integrated() {
        let mut c = TimingCollector::new("trace-tc2");
        c.record_integrated("health_gate_evaluation", 55.0);
        assert_eq!(c.integrated_count("health_gate_evaluation"), 1);
    }

    #[test]
    fn test_collector_record_cold_start() {
        let mut c = TimingCollector::new("trace-tc3");
        c.record_cold_start("lifecycle_transition", 25.0);
        // Cold start shows up in synthesized measurements
        c.record_baseline("lifecycle_transition", 100.0);
        c.record_integrated("lifecycle_transition", 110.0);
        let measurements = c.to_measurements();
        assert_eq!(measurements.len(), 1);
        assert!((measurements[0].cold_start_ms - 25.0).abs() < 0.01);
    }

    #[test]
    fn test_collector_measured_paths_requires_both() {
        let mut c = TimingCollector::new("trace-tc4");
        c.record_baseline("path_a", 100.0);
        // path_a has baseline only — not in measured_paths
        assert!(c.measured_paths().is_empty());
        c.record_integrated("path_a", 110.0);
        assert_eq!(c.measured_paths(), vec!["path_a"]);
    }

    #[test]
    fn test_collector_baseline_stats() {
        let mut c = TimingCollector::new("trace-tc5");
        for i in 1..=100 {
            c.record_baseline("test", i as f64);
        }
        let stats = c.baseline_stats("test").unwrap();
        assert_eq!(stats.count, 100);
        assert!(stats.p95_us >= 90.0);
    }

    #[test]
    fn test_collector_integrated_stats() {
        let mut c = TimingCollector::new("trace-tc6");
        for i in 1..=50 {
            c.record_integrated("test", i as f64 * 2.0);
        }
        let stats = c.integrated_stats("test").unwrap();
        assert_eq!(stats.count, 50);
    }

    #[test]
    fn test_collector_stats_for_unknown_path() {
        let c = TimingCollector::new("trace-tc7");
        assert!(c.baseline_stats("nope").is_none());
        assert!(c.integrated_stats("nope").is_none());
    }

    // -- TimingCollector → BenchmarkMeasurement synthesis --

    #[test]
    fn test_collector_to_measurements() {
        let mut c = TimingCollector::new("trace-syn1");
        for i in 0..20 {
            c.record_baseline("lifecycle_transition", 100.0 + i as f64);
            c.record_integrated("lifecycle_transition", 110.0 + i as f64);
        }
        c.record_cold_start("lifecycle_transition", 30.0);

        let m = c.to_measurements();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].hot_path, "lifecycle_transition");
        assert!(m[0].baseline_p95_us > 0.0);
        assert!(m[0].integrated_p95_us > m[0].baseline_p95_us);
        assert!((m[0].cold_start_ms - 30.0).abs() < 0.01);
    }

    #[test]
    fn test_collector_to_measurements_multi_path() {
        let mut c = TimingCollector::new("trace-syn2");
        for path in &["health_gate_evaluation", "fencing_token_acquire"] {
            for i in 0..10 {
                c.record_baseline(path, 50.0 + i as f64);
                c.record_integrated(path, 55.0 + i as f64);
            }
        }
        let m = c.to_measurements();
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn test_collector_to_measurements_default_cold_start() {
        let mut c = TimingCollector::new("trace-syn3");
        c.record_baseline("test", 100.0);
        c.record_integrated("test", 110.0);
        // No cold_start recorded → defaults to 0.0
        let m = c.to_measurements();
        assert_eq!(m[0].cold_start_ms, 0.0);
    }

    // -- TimingCollector → evaluate_against_policy --

    #[test]
    fn test_collector_evaluate_within_budget() {
        let mut c = TimingCollector::new("trace-eval1");
        for i in 0..20 {
            c.record_baseline("lifecycle_transition", 100.0 + i as f64);
            c.record_integrated("lifecycle_transition", 108.0 + i as f64); // ~8% overhead
        }
        c.record_cold_start("lifecycle_transition", 20.0);

        let result = c.evaluate_against_policy(BudgetPolicy::default()).unwrap();
        assert!(result.overall_pass);
    }

    #[test]
    fn test_collector_evaluate_over_budget() {
        let mut c = TimingCollector::new("trace-eval2");
        for i in 0..20 {
            c.record_baseline("lifecycle_transition", 100.0 + i as f64);
            c.record_integrated("lifecycle_transition", 200.0 + i as f64); // 100% overhead
        }
        c.record_cold_start("lifecycle_transition", 10.0);

        let result = c.evaluate_against_policy(BudgetPolicy::default()).unwrap();
        assert!(!result.overall_pass);
    }

    #[test]
    fn test_collector_evaluate_empty_returns_error() {
        let mut c = TimingCollector::new("trace-eval3");
        let err = c
            .evaluate_against_policy(BudgetPolicy::default())
            .unwrap_err();
        assert_eq!(err.code, ERR_NO_MEASUREMENTS);
    }

    // -- TimingCollector events --

    #[test]
    fn test_collector_emits_prf006_on_record() {
        let mut c = TimingCollector::new("trace-ev1");
        c.record_baseline("test", 100.0);
        c.record_integrated("test", 110.0);
        let prf006: Vec<_> = c
            .events()
            .iter()
            .filter(|e| e.code == PRF_006_TIMING_SAMPLE)
            .collect();
        assert_eq!(prf006.len(), 2);
    }

    #[test]
    fn test_collector_emits_prf007_on_synthesis() {
        let mut c = TimingCollector::new("trace-ev2");
        c.record_baseline("test", 100.0);
        c.record_integrated("test", 110.0);
        let _ = c.to_measurements();
        let prf007: Vec<_> = c
            .events()
            .iter()
            .filter(|e| e.code == PRF_007_PERCENTILE_COMPUTED)
            .collect();
        assert_eq!(prf007.len(), 1);
    }

    #[test]
    fn test_collector_emits_prf008_on_cold_start() {
        let mut c = TimingCollector::new("trace-ev3");
        c.record_cold_start("test", 25.0);
        let prf008: Vec<_> = c
            .events()
            .iter()
            .filter(|e| e.code == PRF_008_COLD_START_TIMING)
            .collect();
        assert_eq!(prf008.len(), 1);
    }

    #[test]
    fn test_collector_trace_id_propagation() {
        let mut c = TimingCollector::new("my-trace-99");
        c.record_baseline("test", 100.0);
        for event in c.events() {
            assert_eq!(event.trace_id, "my-trace-99");
        }
    }

    // -- TimingSample serde --

    #[test]
    fn test_timing_sample_serde_roundtrip() {
        let sample = TimingSample {
            hot_path: "lifecycle_transition".into(),
            duration_us: 123.45,
            is_cold_start: false,
        };
        let json = serde_json::to_string(&sample).unwrap();
        let parsed: TimingSample = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.hot_path, "lifecycle_transition");
        assert!(!parsed.is_cold_start);
    }

    // -- Event code constants --

    #[test]
    fn test_timing_event_codes_defined() {
        assert!(!PRF_006_TIMING_SAMPLE.is_empty());
        assert!(!PRF_007_PERCENTILE_COMPUTED.is_empty());
        assert!(!PRF_008_COLD_START_TIMING.is_empty());
    }

    // -- Determinism --

    #[test]
    fn test_percentile_deterministic() {
        let samples: Vec<f64> = vec![10.0, 20.0, 30.0, 40.0, 50.0];
        let s1 = PercentileStats::from_samples(&samples).unwrap();
        let s2 = PercentileStats::from_samples(&samples).unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_collector_measurement_deterministic() {
        let build = || {
            let mut c = TimingCollector::new("det");
            for i in 0..10 {
                c.record_baseline("path", 100.0 + i as f64);
                c.record_integrated("path", 110.0 + i as f64);
            }
            c.record_cold_start("path", 20.0);
            c.to_measurements()
        };
        let m1 = build();
        let m2 = build();
        assert_eq!(m1[0].baseline_p95_us, m2[0].baseline_p95_us);
        assert_eq!(m1[0].integrated_p95_us, m2[0].integrated_p95_us);
    }

    // -- Edge: many samples --

    #[test]
    fn test_percentile_large_sample_set() {
        let samples: Vec<f64> = (1..=10_000).map(|i| i as f64).collect();
        let stats = PercentileStats::from_samples(&samples).unwrap();
        assert_eq!(stats.count, 10_000);
        assert!(stats.p50_us >= 4900.0 && stats.p50_us <= 5100.0);
        assert!(stats.p95_us >= 9400.0 && stats.p95_us <= 9600.0);
        assert!(stats.p99_us >= 9800.0 && stats.p99_us <= 10100.0);
    }

    // -- Edge: unsorted input --

    #[test]
    fn test_percentile_unsorted_input() {
        let samples = vec![50.0, 10.0, 30.0, 40.0, 20.0];
        let stats = PercentileStats::from_samples(&samples).unwrap();
        assert_eq!(stats.min_us, 10.0);
        assert_eq!(stats.max_us, 50.0);
    }

    // -- Full pipeline: collect → synthesize → gate --

    #[test]
    fn test_full_pipeline_all_canonical_within_budget() {
        let mut c = TimingCollector::new("trace-pipeline");
        for path in HotPath::canonical() {
            let label = path.label();
            for i in 0..30 {
                c.record_baseline(label, 100.0 + i as f64);
                c.record_integrated(label, 107.0 + i as f64); // ~7% overhead
            }
            c.record_cold_start(label, 15.0);
        }
        let result = c.evaluate_against_policy(BudgetPolicy::default()).unwrap();
        assert!(result.overall_pass);
        assert_eq!(result.total_paths, 5);
        assert_eq!(result.paths_over_budget, 0);
    }

    #[test]
    fn test_full_pipeline_one_path_over_budget() {
        let mut c = TimingCollector::new("trace-pipeline2");
        // Within budget
        for i in 0..20 {
            c.record_baseline("lifecycle_transition", 100.0 + i as f64);
            c.record_integrated("lifecycle_transition", 107.0 + i as f64);
        }
        c.record_cold_start("lifecycle_transition", 15.0);
        // Over budget
        for i in 0..20 {
            c.record_baseline("health_gate_evaluation", 100.0 + i as f64);
            c.record_integrated("health_gate_evaluation", 200.0 + i as f64); // 100%
        }
        c.record_cold_start("health_gate_evaluation", 10.0);

        let result = c.evaluate_against_policy(BudgetPolicy::default()).unwrap();
        assert!(!result.overall_pass);
        assert_eq!(result.paths_within_budget, 1);
        assert_eq!(result.paths_over_budget, 1);
    }

    // -- NaN/Inf guards --

    #[test]
    fn test_nan_overhead_fails_closed() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-nan");
        let m = BenchmarkMeasurement {
            hot_path: "lifecycle_transition".into(),
            baseline_p50_us: f64::NAN,
            baseline_p95_us: f64::NAN,
            baseline_p99_us: f64::NAN,
            integrated_p50_us: 110.0,
            integrated_p95_us: 110.0,
            integrated_p99_us: 130.0,
            cold_start_ms: 10.0,
        };
        let result = guard.evaluate(&[m]).unwrap();
        assert!(!result.overall_pass, "NaN overhead must fail closed");
    }

    #[test]
    fn test_nan_cold_start_fails_closed() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-nan-cs");
        let m = BenchmarkMeasurement {
            hot_path: "lifecycle_transition".into(),
            baseline_p50_us: 70.0,
            baseline_p95_us: 100.0,
            baseline_p99_us: 130.0,
            integrated_p50_us: 77.0,
            integrated_p95_us: 105.0,
            integrated_p99_us: 135.0,
            cold_start_ms: f64::NAN,
        };
        let result = guard.evaluate(&[m]).unwrap();
        assert!(!result.overall_pass, "NaN cold-start must fail closed");
    }

    #[test]
    fn test_nan_measurement_result_remains_serializable() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-nan-json");
        let m = BenchmarkMeasurement {
            hot_path: "lifecycle_transition".into(),
            baseline_p50_us: f64::NAN,
            baseline_p95_us: f64::NAN,
            baseline_p99_us: f64::NAN,
            integrated_p50_us: f64::INFINITY,
            integrated_p95_us: f64::INFINITY,
            integrated_p99_us: f64::INFINITY,
            cold_start_ms: f64::NAN,
        };

        let result = guard.evaluate(&[m]).unwrap();
        let json = serde_json::to_string(&result).expect("gate result should remain serializable");
        let parsed: GateResult = serde_json::from_str(&json).unwrap();

        assert!(!parsed.overall_pass);
        assert!(
            parsed.path_results[0]
                .measurement
                .baseline_p95_us
                .is_finite()
        );
        assert!(parsed.path_results[0].overhead_p95_pct.is_finite());
        assert!(parsed.path_results[0].cold_start_ms.is_finite());
    }

    #[test]
    fn test_negative_cold_start_fails_closed() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-neg-cs");
        let m = BenchmarkMeasurement {
            hot_path: "lifecycle_transition".into(),
            baseline_p50_us: 70.0,
            baseline_p95_us: 100.0,
            baseline_p99_us: 130.0,
            integrated_p50_us: 77.0,
            integrated_p95_us: 105.0,
            integrated_p99_us: 135.0,
            cold_start_ms: -1.0,
        };

        let result = guard.evaluate(&[m]).unwrap();

        assert!(!result.overall_pass, "negative cold-start must fail closed");
        assert!(
            result.path_results[0]
                .violations
                .iter()
                .any(|violation| violation.contains("cold-start"))
        );
    }

    #[test]
    fn test_inf_cold_start_fails_closed() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-inf-cs");
        let m = BenchmarkMeasurement {
            hot_path: "lifecycle_transition".into(),
            baseline_p50_us: 70.0,
            baseline_p95_us: 100.0,
            baseline_p99_us: 130.0,
            integrated_p50_us: 77.0,
            integrated_p95_us: 105.0,
            integrated_p99_us: 135.0,
            cold_start_ms: f64::INFINITY,
        };

        let result = guard.evaluate(&[m]).unwrap();

        assert!(!result.overall_pass, "Inf cold-start must fail closed");
        assert!(
            result.path_results[0]
                .violations
                .iter()
                .any(|violation| violation.contains("cold-start"))
        );
    }

    #[test]
    fn test_inf_overhead_fails_closed() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-inf");
        let m = BenchmarkMeasurement {
            hot_path: "lifecycle_transition".into(),
            baseline_p50_us: 70.0,
            baseline_p95_us: 100.0,
            baseline_p99_us: 130.0,
            integrated_p50_us: f64::INFINITY,
            integrated_p95_us: f64::INFINITY,
            integrated_p99_us: f64::INFINITY,
            cold_start_ms: 10.0,
        };
        let result = guard.evaluate(&[m]).unwrap();
        assert!(!result.overall_pass, "Inf overhead must fail closed");
    }

    #[test]
    fn test_nan_budget_thresholds_fail_closed() {
        let mut policy = BudgetPolicy::default();
        policy.default_budget = PathBudget {
            max_overhead_p95_pct: f64::NAN,
            max_overhead_p99_pct: f64::NAN,
            max_cold_start_ms: f64::NAN,
        };
        policy.budgets.clear();
        let mut guard = PerformanceBudgetGuard::new(policy, "trace-nan-budget");
        let m = make_measurement("custom_nan_budget_path", 100.0, 101.0, 1.0);

        let result = guard.evaluate(&[m]).unwrap();

        assert!(!result.overall_pass);
        assert_eq!(result.path_results[0].violations.len(), 3);
    }

    #[test]
    fn test_collector_nan_baseline_ignored() {
        let mut c = TimingCollector::new("trace-nan-bl");
        c.record_baseline("test", f64::NAN);
        c.record_baseline("test", 100.0);
        assert_eq!(c.baseline_count("test"), 1);
    }

    #[test]
    fn test_collector_negative_and_zero_baseline_ignored() {
        let mut c = TimingCollector::new("trace-neg-bl");
        c.record_baseline("test", -1.0);
        c.record_baseline("test", 0.0);
        c.record_baseline("test", 100.0);

        assert_eq!(c.baseline_count("test"), 1);
    }

    #[test]
    fn test_collector_nan_integrated_ignored() {
        let mut c = TimingCollector::new("trace-nan-int");
        c.record_integrated("test", f64::NAN);
        c.record_integrated("test", 110.0);
        assert_eq!(c.integrated_count("test"), 1);
    }

    #[test]
    fn test_collector_negative_integrated_ignored() {
        let mut c = TimingCollector::new("trace-neg-int");
        c.record_integrated("test", -1.0);
        c.record_integrated("test", 0.0);
        c.record_integrated("test", 110.0);

        assert_eq!(c.integrated_count("test"), 1);
    }

    #[test]
    fn test_collector_nan_cold_start_ignored() {
        let mut c = TimingCollector::new("trace-nan-cs2");
        c.record_cold_start("test", f64::NAN);
        c.record_baseline("test", 100.0);
        c.record_integrated("test", 110.0);
        let m = c.to_measurements();
        assert_eq!(m[0].cold_start_ms, 0.0, "NaN cold-start must be ignored");
    }

    #[test]
    fn test_collector_negative_cold_start_ignored() {
        let mut c = TimingCollector::new("trace-neg-cs2");
        c.record_cold_start("test", -1.0);
        c.record_baseline("test", 100.0);
        c.record_integrated("test", 110.0);

        let m = c.to_measurements();

        assert_eq!(
            m[0].cold_start_ms, 0.0,
            "negative cold-start must be ignored"
        );
    }

    #[test]
    fn test_collector_inf_samples_ignored() {
        let mut c = TimingCollector::new("trace-inf-bl");
        c.record_baseline("test", f64::INFINITY);
        c.record_baseline("test", f64::NEG_INFINITY);
        c.record_baseline("test", 100.0);
        assert_eq!(c.baseline_count("test"), 1);
    }

    #[test]
    fn test_collector_only_nonfinite_baseline_does_not_measure_path() {
        let mut c = TimingCollector::new("trace-nonfinite-only");
        c.record_baseline("test", f64::NAN);
        c.record_baseline("test", f64::INFINITY);
        c.record_integrated("test", 110.0);

        assert_eq!(c.baseline_count("test"), 0);
        assert!(c.measured_paths().is_empty());
        assert!(c.to_measurements().is_empty());
    }

    #[test]
    fn test_collector_evaluate_only_baseline_returns_no_measurements_error() {
        let mut c = TimingCollector::new("trace-only-baseline");
        c.record_baseline("lifecycle_transition", 100.0);

        let err = c
            .evaluate_against_policy(BudgetPolicy::default())
            .unwrap_err();

        assert_eq!(err.code, ERR_NO_MEASUREMENTS);
    }

    #[test]
    fn push_bounded_zero_capacity_clears_perf_event_window() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn push_bounded_over_capacity_preserves_latest_perf_events() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 3);

        assert_eq!(items, vec![2, 3, 4]);
    }
}
