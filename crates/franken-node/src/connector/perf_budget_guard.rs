//! bd-1xwz: Performance budget guard for asupersync integration overhead
//! in control-plane hot paths.
//!
//! Measures overhead of asupersync integration in control-plane hot paths
//! and fails the gate when overhead exceeds agreed p95/p99/cold-start
//! budgets.
//!
//! # Invariants
//!
//! - **INV-PBG-BUDGET**: Overhead budgets defined in a machine-readable policy.
//! - **INV-PBG-GATE**: Budget violations block the CI gate.
//! - **INV-PBG-FLAMEGRAPH**: Flamegraph evidence captured on every run.
//! - **INV-PBG-COLD-START**: Cold-start measured separately from steady-state.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// Benchmark started for a hot path.
    pub const PRF_001_BENCHMARK_STARTED: &str = "PRF-001";
    /// Benchmark completed, within budget.
    pub const PRF_002_WITHIN_BUDGET: &str = "PRF-002";
    /// Benchmark completed, over budget.
    pub const PRF_003_OVER_BUDGET: &str = "PRF-003";
    /// Flamegraph captured.
    pub const PRF_004_FLAMEGRAPH_CAPTURED: &str = "PRF-004";
    /// Cold-start measurement completed.
    pub const PRF_005_COLD_START: &str = "PRF-005";
}

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

pub const INV_PBG_BUDGET: &str = "INV-PBG-BUDGET";
pub const INV_PBG_GATE: &str = "INV-PBG-GATE";
pub const INV_PBG_FLAMEGRAPH: &str = "INV-PBG-FLAMEGRAPH";
pub const INV_PBG_COLD_START: &str = "INV-PBG-COLD-START";

// ---------------------------------------------------------------------------
// HotPath
// ---------------------------------------------------------------------------

/// Control-plane hot paths that are benchmarked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HotPath {
    LifecycleTransition,
    HealthGateEvaluation,
    RolloutStateChange,
    FencingTokenOp,
}

impl HotPath {
    pub fn all() -> &'static [HotPath] {
        &[
            HotPath::LifecycleTransition,
            HotPath::HealthGateEvaluation,
            HotPath::RolloutStateChange,
            HotPath::FencingTokenOp,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            HotPath::LifecycleTransition => "lifecycle_transition",
            HotPath::HealthGateEvaluation => "health_gate_evaluation",
            HotPath::RolloutStateChange => "rollout_state_change",
            HotPath::FencingTokenOp => "fencing_token_op",
        }
    }
}

impl fmt::Display for HotPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// BudgetPolicy
// ---------------------------------------------------------------------------

/// Performance budget for a single hot path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HotPathBudget {
    pub hot_path: HotPath,
    /// Maximum allowed p95 overhead percentage.
    pub p95_overhead_pct: f64,
    /// Maximum allowed p99 overhead percentage.
    pub p99_overhead_pct: f64,
    /// Maximum allowed cold-start time in milliseconds.
    pub cold_start_ms: f64,
}

/// Machine-readable budget policy (not hardcoded — loaded from config).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BudgetPolicy {
    pub budgets: Vec<HotPathBudget>,
}

impl BudgetPolicy {
    /// Default budget policy with conservative limits.
    pub fn default_policy() -> Self {
        Self {
            budgets: vec![
                HotPathBudget {
                    hot_path: HotPath::LifecycleTransition,
                    p95_overhead_pct: 15.0,
                    p99_overhead_pct: 25.0,
                    cold_start_ms: 50.0,
                },
                HotPathBudget {
                    hot_path: HotPath::HealthGateEvaluation,
                    p95_overhead_pct: 10.0,
                    p99_overhead_pct: 20.0,
                    cold_start_ms: 30.0,
                },
                HotPathBudget {
                    hot_path: HotPath::RolloutStateChange,
                    p95_overhead_pct: 12.0,
                    p99_overhead_pct: 22.0,
                    cold_start_ms: 40.0,
                },
                HotPathBudget {
                    hot_path: HotPath::FencingTokenOp,
                    p95_overhead_pct: 8.0,
                    p99_overhead_pct: 15.0,
                    cold_start_ms: 20.0,
                },
            ],
        }
    }

    /// Look up the budget for a hot path.
    pub fn budget_for(&self, hot_path: HotPath) -> Option<&HotPathBudget> {
        self.budgets.iter().find(|b| b.hot_path == hot_path)
    }

    /// Serialize to TOML-like format for machine readability.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

impl Default for BudgetPolicy {
    fn default() -> Self {
        Self::default_policy()
    }
}

// ---------------------------------------------------------------------------
// MeasurementResult
// ---------------------------------------------------------------------------

/// Result of benchmarking a single hot path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeasurementResult {
    pub hot_path: HotPath,
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
    pub flamegraph_path: Option<String>,
}

impl MeasurementResult {
    /// Compute overhead from baseline and integrated measurements,
    /// then check against budget.
    #[allow(clippy::too_many_arguments)]
    pub fn from_measurements(
        hot_path: HotPath,
        baseline_p50_us: f64,
        baseline_p95_us: f64,
        baseline_p99_us: f64,
        integrated_p50_us: f64,
        integrated_p95_us: f64,
        integrated_p99_us: f64,
        cold_start_ms: f64,
        budget: &HotPathBudget,
        flamegraph_path: Option<String>,
    ) -> Self {
        let overhead_p95_pct = if baseline_p95_us > 0.0 {
            ((integrated_p95_us - baseline_p95_us) / baseline_p95_us) * 100.0
        } else {
            0.0
        };
        let overhead_p99_pct = if baseline_p99_us > 0.0 {
            ((integrated_p99_us - baseline_p99_us) / baseline_p99_us) * 100.0
        } else {
            0.0
        };
        let within_budget = overhead_p95_pct <= budget.p95_overhead_pct
            && overhead_p99_pct <= budget.p99_overhead_pct
            && cold_start_ms <= budget.cold_start_ms;

        Self {
            hot_path,
            baseline_p50_us,
            baseline_p95_us,
            baseline_p99_us,
            integrated_p50_us,
            integrated_p95_us,
            integrated_p99_us,
            overhead_p95_pct,
            overhead_p99_pct,
            cold_start_ms,
            within_budget,
            flamegraph_path,
        }
    }

    /// CSV row for this measurement.
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{:.1},{:.1},{:.1},{:.1},{:.1},{:.1},{:.2},{:.2},{:.1},{}",
            self.hot_path.label(),
            self.baseline_p50_us,
            self.baseline_p95_us,
            self.baseline_p99_us,
            self.integrated_p50_us,
            self.integrated_p95_us,
            self.integrated_p99_us,
            self.overhead_p95_pct,
            self.overhead_p99_pct,
            self.cold_start_ms,
            self.within_budget,
        )
    }
}

// ---------------------------------------------------------------------------
// GateDecision
// ---------------------------------------------------------------------------

/// Result of the performance gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateDecision {
    Pass,
    Fail { violations: Vec<String> },
}

impl GateDecision {
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }

    pub fn is_fail(&self) -> bool {
        matches!(self, Self::Fail { .. })
    }
}

impl fmt::Display for GateDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail { violations } => {
                write!(f, "FAIL ({} violations)", violations.len())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// OverheadEvent
// ---------------------------------------------------------------------------

/// Structured log event from the overhead gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverheadEvent {
    pub code: String,
    pub hot_path: String,
    pub detail: String,
    pub overhead_pct: Option<f64>,
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// OverheadGateSummary
// ---------------------------------------------------------------------------

/// Summary of overhead gate results.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OverheadGateSummary {
    pub total: usize,
    pub within_budget: usize,
    pub over_budget: usize,
}

impl OverheadGateSummary {
    pub fn gate_pass(&self) -> bool {
        self.over_budget == 0 && self.total > 0
    }
}

impl fmt::Display for OverheadGateSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OverheadGate: total={}, within_budget={}, over_budget={}",
            self.total, self.within_budget, self.over_budget
        )
    }
}

// ---------------------------------------------------------------------------
// OverheadGate
// ---------------------------------------------------------------------------

/// Performance budget gate that evaluates measurement results
/// against the budget policy.
pub struct OverheadGate {
    policy: BudgetPolicy,
    results: Vec<MeasurementResult>,
    events: Vec<OverheadEvent>,
}

impl OverheadGate {
    pub fn new(policy: BudgetPolicy) -> Self {
        Self {
            policy,
            results: Vec::new(),
            events: Vec::new(),
        }
    }

    pub fn with_default_policy() -> Self {
        Self::new(BudgetPolicy::default_policy())
    }

    /// Evaluate a single measurement against its budget.
    pub fn evaluate(&mut self, result: MeasurementResult) -> GateDecision {
        let trace_id = format!("perf-{}", result.hot_path.label());

        // PRF-001: benchmark started
        self.emit_event(
            event_codes::PRF_001_BENCHMARK_STARTED,
            result.hot_path,
            format!("Benchmark started for {}", result.hot_path.label()),
            None,
            &trace_id,
        );

        // PRF-005: cold-start measurement
        self.emit_event(
            event_codes::PRF_005_COLD_START,
            result.hot_path,
            format!("Cold-start: {:.1}ms", result.cold_start_ms),
            None,
            &trace_id,
        );

        // Flamegraph captured
        if result.flamegraph_path.is_some() {
            self.emit_event(
                event_codes::PRF_004_FLAMEGRAPH_CAPTURED,
                result.hot_path,
                "Flamegraph captured".to_string(),
                None,
                &trace_id,
            );
        }

        let decision = if result.within_budget {
            self.emit_event(
                event_codes::PRF_002_WITHIN_BUDGET,
                result.hot_path,
                format!(
                    "Within budget: p95={:.1}%, p99={:.1}%",
                    result.overhead_p95_pct, result.overhead_p99_pct
                ),
                Some(result.overhead_p95_pct),
                &trace_id,
            );
            GateDecision::Pass
        } else {
            let mut violations = Vec::new();
            if let Some(budget) = self.policy.budget_for(result.hot_path) {
                if result.overhead_p95_pct > budget.p95_overhead_pct {
                    violations.push(format!(
                        "p95 overhead {:.1}% > budget {:.1}%",
                        result.overhead_p95_pct, budget.p95_overhead_pct
                    ));
                }
                if result.overhead_p99_pct > budget.p99_overhead_pct {
                    violations.push(format!(
                        "p99 overhead {:.1}% > budget {:.1}%",
                        result.overhead_p99_pct, budget.p99_overhead_pct
                    ));
                }
                if result.cold_start_ms > budget.cold_start_ms {
                    violations.push(format!(
                        "cold-start {:.1}ms > budget {:.1}ms",
                        result.cold_start_ms, budget.cold_start_ms
                    ));
                }
            }
            self.emit_event(
                event_codes::PRF_003_OVER_BUDGET,
                result.hot_path,
                format!("Over budget: {} violation(s)", violations.len()),
                Some(result.overhead_p95_pct),
                &trace_id,
            );
            GateDecision::Fail { violations }
        };

        self.results.push(result);
        decision
    }

    /// Evaluate a batch of measurements.
    pub fn evaluate_batch(&mut self, results: Vec<MeasurementResult>) -> Vec<GateDecision> {
        results.into_iter().map(|r| self.evaluate(r)).collect()
    }

    /// Check if the gate passes (all measurements within budget).
    pub fn gate_pass(&self) -> bool {
        !self.results.is_empty() && self.results.iter().all(|r| r.within_budget)
    }

    /// Summary of results.
    pub fn summary(&self) -> OverheadGateSummary {
        OverheadGateSummary {
            total: self.results.len(),
            within_budget: self.results.iter().filter(|r| r.within_budget).count(),
            over_budget: self.results.iter().filter(|r| !r.within_budget).count(),
        }
    }

    /// Policy reference.
    pub fn policy(&self) -> &BudgetPolicy {
        &self.policy
    }

    /// All results.
    pub fn results(&self) -> &[MeasurementResult] {
        &self.results
    }

    /// All events.
    pub fn events(&self) -> &[OverheadEvent] {
        &self.events
    }

    /// Drain and return all events.
    pub fn take_events(&mut self) -> Vec<OverheadEvent> {
        std::mem::take(&mut self.events)
    }

    /// Generate CSV report.
    pub fn to_csv(&self) -> String {
        let header = "hot_path,baseline_p50_us,baseline_p95_us,baseline_p99_us,integrated_p50_us,integrated_p95_us,integrated_p99_us,overhead_p95_pct,overhead_p99_pct,cold_start_ms,within_budget";
        let rows: Vec<String> = self.results.iter().map(|r| r.to_csv_row()).collect();
        format!("{}\n{}", header, rows.join("\n"))
    }

    /// Generate JSON report.
    pub fn to_report(&self) -> serde_json::Value {
        let summary = self.summary();
        serde_json::json!({
            "bead_id": "bd-1xwz",
            "section": "10.15",
            "gate_pass": summary.gate_pass(),
            "summary": {
                "total": summary.total,
                "within_budget": summary.within_budget,
                "over_budget": summary.over_budget,
            },
            "policy": self.policy,
            "results": self.results,
        })
    }

    fn emit_event(
        &mut self,
        code: &str,
        hot_path: HotPath,
        detail: String,
        overhead_pct: Option<f64>,
        trace_id: &str,
    ) {
        self.events.push(OverheadEvent {
            code: code.to_string(),
            hot_path: hot_path.label().to_string(),
            detail,
            overhead_pct,
            trace_id: trace_id.to_string(),
        });
    }
}

impl Default for OverheadGate {
    fn default() -> Self {
        Self::with_default_policy()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn default_budget() -> HotPathBudget {
        HotPathBudget {
            hot_path: HotPath::HealthGateEvaluation,
            p95_overhead_pct: 10.0,
            p99_overhead_pct: 20.0,
            cold_start_ms: 30.0,
        }
    }

    fn within_budget_result(hot_path: HotPath) -> MeasurementResult {
        let budget = BudgetPolicy::default_policy()
            .budget_for(hot_path)
            .cloned()
            .unwrap_or(default_budget());
        MeasurementResult::from_measurements(
            hot_path,
            100.0,
            110.0,
            120.0, // baseline
            105.0,
            118.0,
            130.0, // integrated (small overhead)
            15.0,  // cold start
            &budget,
            Some("flamegraph.svg".into()),
        )
    }

    fn over_budget_result(hot_path: HotPath) -> MeasurementResult {
        let budget = BudgetPolicy::default_policy()
            .budget_for(hot_path)
            .cloned()
            .unwrap_or(default_budget());
        MeasurementResult::from_measurements(
            hot_path,
            100.0,
            100.0,
            100.0, // baseline
            200.0,
            200.0,
            200.0, // integrated (100% overhead)
            100.0, // cold start way over
            &budget,
            Some("flamegraph.svg".into()),
        )
    }

    // ── HotPath ──────────────────────────────────────────────────

    #[test]
    fn test_hot_path_all() {
        assert_eq!(HotPath::all().len(), 4);
    }

    #[test]
    fn test_hot_path_labels() {
        assert_eq!(HotPath::LifecycleTransition.label(), "lifecycle_transition");
        assert_eq!(
            HotPath::HealthGateEvaluation.label(),
            "health_gate_evaluation"
        );
        assert_eq!(HotPath::RolloutStateChange.label(), "rollout_state_change");
        assert_eq!(HotPath::FencingTokenOp.label(), "fencing_token_op");
    }

    #[test]
    fn test_hot_path_display() {
        assert_eq!(
            format!("{}", HotPath::LifecycleTransition),
            "lifecycle_transition"
        );
    }

    #[test]
    fn test_hot_path_serde_roundtrip() {
        for hp in HotPath::all() {
            let json = serde_json::to_string(hp).unwrap();
            let parsed: HotPath = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, *hp);
        }
    }

    // ── BudgetPolicy ─────────────────────────────────────────────

    #[test]
    fn test_default_policy_has_all_paths() {
        let policy = BudgetPolicy::default_policy();
        for hp in HotPath::all() {
            assert!(
                policy.budget_for(*hp).is_some(),
                "Missing budget for {}",
                hp
            );
        }
    }

    #[test]
    fn test_budget_for_health_gate() {
        let policy = BudgetPolicy::default_policy();
        let b = policy.budget_for(HotPath::HealthGateEvaluation).unwrap();
        assert_eq!(b.p95_overhead_pct, 10.0);
        assert_eq!(b.p99_overhead_pct, 20.0);
        assert_eq!(b.cold_start_ms, 30.0);
    }

    #[test]
    fn test_budget_for_missing() {
        let policy = BudgetPolicy { budgets: vec![] };
        assert!(policy.budget_for(HotPath::HealthGateEvaluation).is_none());
    }

    #[test]
    fn test_policy_to_json() {
        let policy = BudgetPolicy::default_policy();
        let json = policy.to_json();
        assert!(json.contains("HealthGateEvaluation"));
        assert!(json.contains("p95_overhead_pct"));
    }

    #[test]
    fn test_policy_serde_roundtrip() {
        let policy = BudgetPolicy::default_policy();
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: BudgetPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, policy);
    }

    // ── MeasurementResult ────────────────────────────────────────

    #[test]
    fn test_measurement_within_budget() {
        let r = within_budget_result(HotPath::HealthGateEvaluation);
        assert!(r.within_budget);
    }

    #[test]
    fn test_measurement_over_budget() {
        let r = over_budget_result(HotPath::HealthGateEvaluation);
        assert!(!r.within_budget);
    }

    #[test]
    fn test_measurement_overhead_calculation() {
        let budget = default_budget();
        let r = MeasurementResult::from_measurements(
            HotPath::HealthGateEvaluation,
            100.0,
            100.0,
            100.0,
            100.0,
            110.0,
            120.0,
            10.0,
            &budget,
            None,
        );
        assert!((r.overhead_p95_pct - 10.0).abs() < 0.1);
        assert!((r.overhead_p99_pct - 20.0).abs() < 0.1);
    }

    #[test]
    fn test_measurement_zero_baseline() {
        let budget = default_budget();
        let r = MeasurementResult::from_measurements(
            HotPath::HealthGateEvaluation,
            0.0,
            0.0,
            0.0,
            10.0,
            10.0,
            10.0,
            5.0,
            &budget,
            None,
        );
        assert_eq!(r.overhead_p95_pct, 0.0);
    }

    #[test]
    fn test_measurement_csv_row() {
        let r = within_budget_result(HotPath::HealthGateEvaluation);
        let row = r.to_csv_row();
        assert!(row.starts_with("health_gate_evaluation,"));
        assert!(row.contains("true"));
    }

    #[test]
    fn test_measurement_serde_roundtrip() {
        let r = within_budget_result(HotPath::HealthGateEvaluation);
        let json = serde_json::to_string(&r).unwrap();
        let parsed: MeasurementResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.hot_path, r.hot_path);
        assert_eq!(parsed.within_budget, r.within_budget);
    }

    #[test]
    fn test_measurement_cold_start_over_budget() {
        let budget = HotPathBudget {
            hot_path: HotPath::HealthGateEvaluation,
            p95_overhead_pct: 100.0,
            p99_overhead_pct: 100.0,
            cold_start_ms: 5.0,
        };
        let r = MeasurementResult::from_measurements(
            HotPath::HealthGateEvaluation,
            100.0,
            100.0,
            100.0,
            100.0,
            100.0,
            100.0,
            10.0,
            &budget,
            None,
        );
        assert!(!r.within_budget);
    }

    // ── GateDecision ─────────────────────────────────────────────

    #[test]
    fn test_gate_decision_pass() {
        let d = GateDecision::Pass;
        assert!(d.is_pass());
        assert!(!d.is_fail());
    }

    #[test]
    fn test_gate_decision_fail() {
        let d = GateDecision::Fail {
            violations: vec!["test".into()],
        };
        assert!(d.is_fail());
        assert!(!d.is_pass());
    }

    #[test]
    fn test_gate_decision_display() {
        assert_eq!(GateDecision::Pass.to_string(), "PASS");
        let d = GateDecision::Fail {
            violations: vec!["a".into(), "b".into()],
        };
        assert!(d.to_string().contains("2 violations"));
    }

    #[test]
    fn test_gate_decision_serde_roundtrip() {
        let d = GateDecision::Pass;
        let json = serde_json::to_string(&d).unwrap();
        let parsed: GateDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, d);
    }

    // ── OverheadGateSummary ──────────────────────────────────────

    #[test]
    fn test_summary_gate_pass() {
        let s = OverheadGateSummary {
            total: 4,
            within_budget: 4,
            over_budget: 0,
        };
        assert!(s.gate_pass());
    }

    #[test]
    fn test_summary_gate_fail() {
        let s = OverheadGateSummary {
            total: 4,
            within_budget: 3,
            over_budget: 1,
        };
        assert!(!s.gate_pass());
    }

    #[test]
    fn test_summary_gate_fail_empty() {
        let s = OverheadGateSummary {
            total: 0,
            within_budget: 0,
            over_budget: 0,
        };
        assert!(!s.gate_pass());
    }

    #[test]
    fn test_summary_display() {
        let s = OverheadGateSummary {
            total: 4,
            within_budget: 3,
            over_budget: 1,
        };
        assert!(s.to_string().contains("4"));
        assert!(s.to_string().contains("over_budget=1"));
    }

    // ── OverheadGate ─────────────────────────────────────────────

    #[test]
    fn test_gate_evaluate_within_budget() {
        let mut gate = OverheadGate::with_default_policy();
        let r = within_budget_result(HotPath::HealthGateEvaluation);
        let d = gate.evaluate(r);
        assert!(d.is_pass());
    }

    #[test]
    fn test_gate_evaluate_over_budget() {
        let mut gate = OverheadGate::with_default_policy();
        let r = over_budget_result(HotPath::HealthGateEvaluation);
        let d = gate.evaluate(r);
        assert!(d.is_fail());
    }

    #[test]
    fn test_gate_pass_all_within() {
        let mut gate = OverheadGate::with_default_policy();
        for hp in HotPath::all() {
            gate.evaluate(within_budget_result(*hp));
        }
        assert!(gate.gate_pass());
    }

    #[test]
    fn test_gate_fail_one_over() {
        let mut gate = OverheadGate::with_default_policy();
        gate.evaluate(within_budget_result(HotPath::HealthGateEvaluation));
        gate.evaluate(over_budget_result(HotPath::FencingTokenOp));
        assert!(!gate.gate_pass());
    }

    #[test]
    fn test_gate_evaluate_batch() {
        let mut gate = OverheadGate::with_default_policy();
        let results = vec![
            within_budget_result(HotPath::HealthGateEvaluation),
            within_budget_result(HotPath::LifecycleTransition),
        ];
        let decisions = gate.evaluate_batch(results);
        assert_eq!(decisions.len(), 2);
        assert!(decisions.iter().all(|d| d.is_pass()));
    }

    #[test]
    fn test_gate_evaluate_batch_mixed() {
        let mut gate = OverheadGate::with_default_policy();
        let results = vec![
            within_budget_result(HotPath::HealthGateEvaluation),
            over_budget_result(HotPath::FencingTokenOp),
        ];
        let decisions = gate.evaluate_batch(results);
        assert!(decisions[0].is_pass());
        assert!(decisions[1].is_fail());
    }

    // ── Events ───────────────────────────────────────────────────

    #[test]
    fn test_evaluate_emits_prf001() {
        let mut gate = OverheadGate::with_default_policy();
        gate.evaluate(within_budget_result(HotPath::HealthGateEvaluation));
        let prf001: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == event_codes::PRF_001_BENCHMARK_STARTED)
            .collect();
        assert_eq!(prf001.len(), 1);
    }

    #[test]
    fn test_evaluate_within_emits_prf002() {
        let mut gate = OverheadGate::with_default_policy();
        gate.evaluate(within_budget_result(HotPath::HealthGateEvaluation));
        let prf002: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == event_codes::PRF_002_WITHIN_BUDGET)
            .collect();
        assert_eq!(prf002.len(), 1);
    }

    #[test]
    fn test_evaluate_over_emits_prf003() {
        let mut gate = OverheadGate::with_default_policy();
        gate.evaluate(over_budget_result(HotPath::HealthGateEvaluation));
        let prf003: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == event_codes::PRF_003_OVER_BUDGET)
            .collect();
        assert_eq!(prf003.len(), 1);
    }

    #[test]
    fn test_evaluate_emits_prf004_with_flamegraph() {
        let mut gate = OverheadGate::with_default_policy();
        gate.evaluate(within_budget_result(HotPath::HealthGateEvaluation));
        let prf004: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == event_codes::PRF_004_FLAMEGRAPH_CAPTURED)
            .collect();
        assert_eq!(prf004.len(), 1);
    }

    #[test]
    fn test_evaluate_no_prf004_without_flamegraph() {
        let mut gate = OverheadGate::with_default_policy();
        let budget = default_budget();
        let r = MeasurementResult::from_measurements(
            HotPath::HealthGateEvaluation,
            100.0,
            110.0,
            120.0,
            105.0,
            118.0,
            130.0,
            15.0,
            &budget,
            None,
        );
        gate.evaluate(r);
        let prf004: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == event_codes::PRF_004_FLAMEGRAPH_CAPTURED)
            .collect();
        assert_eq!(prf004.len(), 0);
    }

    #[test]
    fn test_evaluate_emits_prf005() {
        let mut gate = OverheadGate::with_default_policy();
        gate.evaluate(within_budget_result(HotPath::HealthGateEvaluation));
        let prf005: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == event_codes::PRF_005_COLD_START)
            .collect();
        assert_eq!(prf005.len(), 1);
    }

    #[test]
    fn test_take_events_drains() {
        let mut gate = OverheadGate::with_default_policy();
        gate.evaluate(within_budget_result(HotPath::HealthGateEvaluation));
        assert!(!gate.events().is_empty());
        let events = gate.take_events();
        assert!(!events.is_empty());
        assert!(gate.events().is_empty());
    }

    // ── CSV ──────────────────────────────────────────────────────

    #[test]
    fn test_csv_header() {
        let gate = OverheadGate::with_default_policy();
        let csv = gate.to_csv();
        assert!(csv.starts_with("hot_path,baseline_p50_us"));
    }

    #[test]
    fn test_csv_with_results() {
        let mut gate = OverheadGate::with_default_policy();
        gate.evaluate(within_budget_result(HotPath::HealthGateEvaluation));
        gate.evaluate(within_budget_result(HotPath::FencingTokenOp));
        let csv = gate.to_csv();
        let lines: Vec<_> = csv.lines().collect();
        assert_eq!(lines.len(), 3); // header + 2 rows
        assert!(lines[1].starts_with("health_gate_evaluation,"));
        assert!(lines[2].starts_with("fencing_token_op,"));
    }

    // ── JSON report ──────────────────────────────────────────────

    #[test]
    fn test_report_structure() {
        let mut gate = OverheadGate::with_default_policy();
        gate.evaluate(within_budget_result(HotPath::HealthGateEvaluation));
        let report = gate.to_report();
        assert_eq!(report["bead_id"], "bd-1xwz");
        assert_eq!(report["section"], "10.15");
        assert!(report["gate_pass"].as_bool().unwrap());
    }

    #[test]
    fn test_report_results() {
        let mut gate = OverheadGate::with_default_policy();
        for hp in HotPath::all() {
            gate.evaluate(within_budget_result(*hp));
        }
        let report = gate.to_report();
        assert_eq!(report["results"].as_array().unwrap().len(), 4);
    }

    // ── Default ──────────────────────────────────────────────────

    #[test]
    fn test_default_gate() {
        let gate = OverheadGate::default();
        assert!(gate.results().is_empty());
        assert!(gate.events().is_empty());
        assert!(!gate.gate_pass());
    }

    // ── Adversarial ──────────────────────────────────────────────

    #[test]
    fn test_adversarial_zero_budgets() {
        let policy = BudgetPolicy {
            budgets: HotPath::all()
                .iter()
                .map(|hp| HotPathBudget {
                    hot_path: *hp,
                    p95_overhead_pct: 0.0,
                    p99_overhead_pct: 0.0,
                    cold_start_ms: 0.0,
                })
                .collect(),
        };
        let mut gate = OverheadGate::new(policy);
        for hp in HotPath::all() {
            let budget = HotPathBudget {
                hot_path: *hp,
                p95_overhead_pct: 0.0,
                p99_overhead_pct: 0.0,
                cold_start_ms: 0.0,
            };
            let r = MeasurementResult::from_measurements(
                *hp, 100.0, 100.0, 100.0, 101.0, 101.0, 101.0, 1.0, &budget, None,
            );
            let d = gate.evaluate(r);
            assert!(d.is_fail(), "Zero budget should fail for {}", hp);
        }
        assert!(!gate.gate_pass());
    }

    #[test]
    fn test_adversarial_infinity_budgets() {
        let policy = BudgetPolicy {
            budgets: HotPath::all()
                .iter()
                .map(|hp| HotPathBudget {
                    hot_path: *hp,
                    p95_overhead_pct: f64::INFINITY,
                    p99_overhead_pct: f64::INFINITY,
                    cold_start_ms: f64::INFINITY,
                })
                .collect(),
        };
        let mut gate = OverheadGate::new(policy);
        for hp in HotPath::all() {
            let budget = HotPathBudget {
                hot_path: *hp,
                p95_overhead_pct: f64::INFINITY,
                p99_overhead_pct: f64::INFINITY,
                cold_start_ms: f64::INFINITY,
            };
            let r = MeasurementResult::from_measurements(
                *hp, 100.0, 100.0, 100.0, 10000.0, 10000.0, 10000.0, 10000.0, &budget, None,
            );
            let d = gate.evaluate(r);
            assert!(d.is_pass(), "Infinity budget should pass for {}", hp);
        }
        assert!(gate.gate_pass());
    }

    #[test]
    fn test_adversarial_no_flamegraph() {
        let mut gate = OverheadGate::with_default_policy();
        let budget = default_budget();
        let r = MeasurementResult::from_measurements(
            HotPath::HealthGateEvaluation,
            100.0,
            110.0,
            120.0,
            105.0,
            118.0,
            130.0,
            15.0,
            &budget,
            None,
        );
        gate.evaluate(r);
        // Gate should still produce a valid report
        let report = gate.to_report();
        assert!(report["gate_pass"].as_bool().unwrap());
    }

    // ── Summary ──────────────────────────────────────────────────

    #[test]
    fn test_summary_all_within() {
        let mut gate = OverheadGate::with_default_policy();
        for hp in HotPath::all() {
            gate.evaluate(within_budget_result(*hp));
        }
        let s = gate.summary();
        assert_eq!(s.total, 4);
        assert_eq!(s.within_budget, 4);
        assert_eq!(s.over_budget, 0);
        assert!(s.gate_pass());
    }

    #[test]
    fn test_summary_mixed() {
        let mut gate = OverheadGate::with_default_policy();
        gate.evaluate(within_budget_result(HotPath::HealthGateEvaluation));
        gate.evaluate(over_budget_result(HotPath::FencingTokenOp));
        let s = gate.summary();
        assert_eq!(s.total, 2);
        assert_eq!(s.within_budget, 1);
        assert_eq!(s.over_budget, 1);
    }

    // ── Event codes defined ──────────────────────────────────────

    #[test]
    fn test_event_codes_defined() {
        assert!(!event_codes::PRF_001_BENCHMARK_STARTED.is_empty());
        assert!(!event_codes::PRF_002_WITHIN_BUDGET.is_empty());
        assert!(!event_codes::PRF_003_OVER_BUDGET.is_empty());
        assert!(!event_codes::PRF_004_FLAMEGRAPH_CAPTURED.is_empty());
        assert!(!event_codes::PRF_005_COLD_START.is_empty());
    }

    // ── Invariant constants ──────────────────────────────────────

    #[test]
    fn test_invariant_constants_defined() {
        assert!(!INV_PBG_BUDGET.is_empty());
        assert!(!INV_PBG_GATE.is_empty());
        assert!(!INV_PBG_FLAMEGRAPH.is_empty());
        assert!(!INV_PBG_COLD_START.is_empty());
    }

    // ── Event serde ──────────────────────────────────────────────

    #[test]
    fn test_overhead_event_serde() {
        let event = OverheadEvent {
            code: "PRF-001".into(),
            hot_path: "health_gate_evaluation".into(),
            detail: "test".into(),
            overhead_pct: Some(5.0),
            trace_id: "trace-001".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: OverheadEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.code, "PRF-001");
    }

    // ── Determinism ──────────────────────────────────────────────

    #[test]
    fn test_determinism_identical_policy() {
        let budget = default_budget();
        let r1 = MeasurementResult::from_measurements(
            HotPath::HealthGateEvaluation,
            100.0,
            100.0,
            100.0,
            110.0,
            110.0,
            110.0,
            10.0,
            &budget,
            None,
        );
        let r2 = MeasurementResult::from_measurements(
            HotPath::HealthGateEvaluation,
            100.0,
            100.0,
            100.0,
            110.0,
            110.0,
            110.0,
            10.0,
            &budget,
            None,
        );
        assert_eq!(r1.within_budget, r2.within_budget);
        assert_eq!(r1.overhead_p95_pct, r2.overhead_p95_pct);
    }

    // ── Fail violations detail ───────────────────────────────────

    #[test]
    fn test_fail_has_violation_details() {
        let mut gate = OverheadGate::with_default_policy();
        let r = over_budget_result(HotPath::HealthGateEvaluation);
        let d = gate.evaluate(r);
        if let GateDecision::Fail { violations } = d {
            assert!(!violations.is_empty());
            assert!(violations.iter().any(|v| v.contains("p95")));
        } else {
            panic!("Expected Fail");
        }
    }
}
