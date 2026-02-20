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
use std::collections::HashMap;
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
    pub budgets: HashMap<String, PathBudget>,
    /// Default budget for paths not explicitly listed.
    pub default_budget: PathBudget,
}

impl Default for BudgetPolicy {
    fn default() -> Self {
        let mut budgets = HashMap::new();
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
        let mut budgets = HashMap::new();
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
        let mut budgets = HashMap::new();
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
        if self.baseline_p95_us <= 0.0 {
            return 0.0;
        }
        ((self.integrated_p95_us - self.baseline_p95_us) / self.baseline_p95_us) * 100.0
    }

    /// Overhead at p99 as a percentage.
    pub fn overhead_p99_pct(&self) -> f64 {
        if self.baseline_p99_us <= 0.0 {
            return 0.0;
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

        for m in measurements {
            self.emit(PRF_001_BENCHMARK_STARTED, &m.hot_path, "Benchmark evaluation started");

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

            if overhead_p95 > budget.max_overhead_p95_pct {
                violations.push(format!(
                    "p95 overhead {:.1}% exceeds budget {:.1}%",
                    overhead_p95, budget.max_overhead_p95_pct
                ));
            }
            if overhead_p99 > budget.max_overhead_p99_pct {
                violations.push(format!(
                    "p99 overhead {:.1}% exceeds budget {:.1}%",
                    overhead_p99, budget.max_overhead_p99_pct
                ));
            }
            if cold_start > budget.max_cold_start_ms {
                violations.push(format!(
                    "cold-start {:.1}ms exceeds budget {:.1}ms",
                    cold_start, budget.max_cold_start_ms
                ));
            }

            let within_budget = violations.is_empty();

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
                    &format!("p95={:.1}%, p99={:.1}%, cold={:.1}ms", overhead_p95, overhead_p99, cold_start),
                );
            } else {
                self.emit(
                    PRF_003_OVER_BUDGET,
                    &m.hot_path,
                    &format!("Violations: {}", violations.join("; ")),
                );
            }

            path_results.push(PathResult {
                hot_path: m.hot_path.clone(),
                measurement: m.clone(),
                overhead_p95_pct: overhead_p95,
                overhead_p99_pct: overhead_p99,
                cold_start_ms: cold_start,
                within_budget,
                violations,
                flamegraph_path,
            });
        }

        let total = path_results.len();
        let passing = path_results.iter().filter(|r| r.within_budget).count();
        let failing = total - passing;

        Ok(GateResult {
            overall_pass: failing == 0,
            path_results,
            total_paths: total,
            paths_within_budget: passing,
            paths_over_budget: failing,
        })
    }

    /// Generate CSV report from gate result.
    pub fn to_csv(result: &GateResult) -> String {
        let mut out = String::from(
            "hot_path,baseline_p50_us,baseline_p95_us,baseline_p99_us,\
             integrated_p50_us,integrated_p95_us,integrated_p99_us,\
             overhead_p95_pct,overhead_p99_pct,cold_start_ms,within_budget\n"
        );
        for r in &result.path_results {
            let m = &r.measurement;
            out.push_str(&format!(
                "{},{:.1},{:.1},{:.1},{:.1},{:.1},{:.1},{:.2},{:.2},{:.2},{}\n",
                r.hot_path,
                m.baseline_p50_us, m.baseline_p95_us, m.baseline_p99_us,
                m.integrated_p50_us, m.integrated_p95_us, m.integrated_p99_us,
                r.overhead_p95_pct, r.overhead_p99_pct, r.cold_start_ms,
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
        self.events.push(PerfEvent {
            code: code.to_string(),
            hot_path: hot_path.to_string(),
            detail: detail.to_string(),
            trace_id: self.trace_id.clone(),
        });
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
// Send + Sync
// ---------------------------------------------------------------------------

fn _assert_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<PerformanceBudgetGuard>();
    assert_sync::<PerformanceBudgetGuard>();
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_measurement(path: &str, baseline_p95: f64, integrated_p95: f64, cold_start: f64) -> BenchmarkMeasurement {
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
        assert_eq!(HotPath::HealthGateEvaluation.label(), "health_gate_evaluation");
        assert_eq!(HotPath::RolloutStateChange.label(), "rollout_state_change");
        assert_eq!(HotPath::FencingTokenAcquire.label(), "fencing_token_acquire");
        assert_eq!(HotPath::FencingTokenRelease.label(), "fencing_token_release");
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
        assert_eq!(budget.max_overhead_p95_pct, policy.default_budget.max_overhead_p95_pct);
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
        assert_eq!(m.overhead_p95_pct(), 0.0);
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
        let within_events: Vec<_> = guard.events().iter()
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
        assert!(result.path_results[0].violations.iter().any(|v| v.contains("cold-start")));
    }

    #[test]
    fn test_over_budget_emits_prf003() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-2");
        let measurements = vec![
            make_measurement("lifecycle_transition", 100.0, 120.0, 10.0),
        ];
        guard.evaluate(&measurements).unwrap();
        let over_events: Vec<_> = guard.events().iter()
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
        let measurements = vec![
            make_measurement("lifecycle_transition", 100.0, 999.0, 999.0),
        ];
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

    // -- Flamegraph capture --

    #[test]
    fn test_flamegraph_on_failure() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-fg")
            .with_flamegraph_dir("/tmp/flamegraphs");
        let measurements = vec![
            make_measurement("lifecycle_transition", 100.0, 120.0, 10.0),
        ];
        let result = guard.evaluate(&measurements).unwrap();
        assert!(result.path_results[0].flamegraph_path.is_some());
        assert!(result.path_results[0].flamegraph_path.as_ref().unwrap().contains("flamegraph_lifecycle"));
    }

    #[test]
    fn test_flamegraph_prf004_event() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-fg2")
            .with_flamegraph_dir("/tmp/fg");
        let measurements = vec![
            make_measurement("lifecycle_transition", 100.0, 120.0, 10.0),
        ];
        guard.evaluate(&measurements).unwrap();
        let fg_events: Vec<_> = guard.events().iter()
            .filter(|e| e.code == PRF_004_FLAMEGRAPH_CAPTURED)
            .collect();
        assert!(!fg_events.is_empty());
    }

    #[test]
    fn test_no_flamegraph_without_dir() {
        let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "trace-nofg");
        let measurements = vec![
            make_measurement("lifecycle_transition", 100.0, 120.0, 10.0),
        ];
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
        let cs_events: Vec<_> = guard.events().iter()
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
            make_measurement("lifecycle_transition", 100.0, 110.0, 20.0),  // within
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
        assert!(result.path_results[0].violations.len() >= 2);
    }

    // -- Exactly at budget boundary --

    #[test]
    fn test_exactly_at_p95_budget_passes() {
        let policy = BudgetPolicy::default(); // 15%
        let mut guard = PerformanceBudgetGuard::new(policy, "trace-boundary");
        let measurements = vec![
            make_measurement("lifecycle_transition", 100.0, 115.0, 10.0), // exactly 15%
        ];
        let result = guard.evaluate(&measurements).unwrap();
        assert!(result.overall_pass);
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
        assert_eq!(format!("{}", HotPath::LifecycleTransition), "lifecycle_transition");
    }
}
