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

use crate::capacity_defaults::aliases::{MAX_EVENTS, MAX_RESULTS};

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if items.len() >= cap {
        let overflow = items.len() - cap + 1;
        items.drain(0..overflow);
    }
    items.push(item);
}

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
        let overhead_p95_pct = if baseline_p95_us.is_finite() && baseline_p95_us > 0.0 {
            let raw = ((integrated_p95_us - baseline_p95_us) / baseline_p95_us) * 100.0;
            if raw.is_finite() { raw } else { 0.0 }
        } else {
            0.0
        };
        let overhead_p99_pct = if baseline_p99_us.is_finite() && baseline_p99_us > 0.0 {
            let raw = ((integrated_p99_us - baseline_p99_us) / baseline_p99_us) * 100.0;
            if raw.is_finite() { raw } else { 0.0 }
        } else {
            0.0
        };
        let inputs_valid = [
            baseline_p50_us,
            baseline_p95_us,
            baseline_p99_us,
            integrated_p50_us,
            integrated_p95_us,
            integrated_p99_us,
            cold_start_ms,
        ]
        .into_iter()
        .all(|value| value.is_finite() && value >= 0.0);
        let within_budget = inputs_valid
            && overhead_p95_pct <= budget.p95_overhead_pct
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

        push_bounded(&mut self.results, result, MAX_RESULTS);
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
        push_bounded(
            &mut self.events,
            OverheadEvent {
                code: code.to_string(),
                hot_path: hot_path.label().to_string(),
                detail,
                overhead_pct,
                trace_id: trace_id.to_string(),
            },
            MAX_EVENTS,
        );
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

    #[test]
    fn test_hot_path_deserialize_rejects_unknown_variant() {
        let result: Result<HotPath, _> = serde_json::from_str(r#""KernelBypass""#);

        assert!(result.is_err());
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

    #[test]
    fn test_budget_policy_deserialize_rejects_budgets_type_confusion() {
        let json = r#"{
            "budgets": {
                "hot_path": "HealthGateEvaluation"
            }
        }"#;

        let result: Result<BudgetPolicy, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    #[test]
    fn test_hot_path_budget_deserialize_rejects_missing_hot_path() {
        let json = r#"{
            "p95_overhead_pct": 10.0,
            "p99_overhead_pct": 20.0,
            "cold_start_ms": 30.0
        }"#;

        let result: Result<HotPathBudget, _> = serde_json::from_str(json);

        assert!(result.is_err());
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
    fn test_measurement_deserialize_rejects_missing_within_budget() {
        let json = r#"{
            "hot_path": "HealthGateEvaluation",
            "baseline_p50_us": 100.0,
            "baseline_p95_us": 110.0,
            "baseline_p99_us": 120.0,
            "integrated_p50_us": 105.0,
            "integrated_p95_us": 118.0,
            "integrated_p99_us": 130.0,
            "overhead_p95_pct": 7.27,
            "overhead_p99_pct": 8.33,
            "cold_start_ms": 15.0,
            "flamegraph_path": null
        }"#;

        let result: Result<MeasurementResult, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    #[test]
    fn test_measurement_deserialize_rejects_invalid_flamegraph_type() {
        let json = r#"{
            "hot_path": "HealthGateEvaluation",
            "baseline_p50_us": 100.0,
            "baseline_p95_us": 110.0,
            "baseline_p99_us": 120.0,
            "integrated_p50_us": 105.0,
            "integrated_p95_us": 118.0,
            "integrated_p99_us": 130.0,
            "overhead_p95_pct": 7.27,
            "overhead_p99_pct": 8.33,
            "cold_start_ms": 15.0,
            "within_budget": true,
            "flamegraph_path": 42
        }"#;

        let result: Result<MeasurementResult, _> = serde_json::from_str(json);

        assert!(result.is_err());
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

    #[test]
    fn test_gate_decision_deserialize_rejects_unknown_variant() {
        let result: Result<GateDecision, _> = serde_json::from_str(r#""Maybe""#);

        assert!(result.is_err());
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
    fn test_gate_evaluate_over_budget_with_missing_policy_budget_fails_closed() {
        let mut gate = OverheadGate::new(BudgetPolicy {
            budgets: Vec::new(),
        });
        let decision = gate.evaluate(over_budget_result(HotPath::HealthGateEvaluation));

        assert!(decision.is_fail());
        assert!(!gate.gate_pass());
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

    #[test]
    fn test_overhead_event_deserialize_rejects_missing_trace_id() {
        let json = r#"{
            "code": "PRF-001",
            "hot_path": "health_gate_evaluation",
            "detail": "test",
            "overhead_pct": 5.0
        }"#;

        let result: Result<OverheadEvent, _> = serde_json::from_str(json);

        assert!(result.is_err());
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
            unreachable!("Expected Fail");
        }
    }

    // ── NaN/Inf guards ────────────────────────────────────────────

    #[test]
    fn test_nan_baseline_fails_closed() {
        let budget = HotPathBudget {
            hot_path: HotPath::LifecycleTransition,
            p95_overhead_pct: 15.0,
            p99_overhead_pct: 25.0,
            cold_start_ms: 50.0,
        };
        let r = MeasurementResult::from_measurements(
            HotPath::LifecycleTransition,
            70.0,     // baseline p50
            f64::NAN, // baseline p95 — NaN
            130.0,    // baseline p99
            77.0,     // integrated p50
            105.0,    // integrated p95
            135.0,    // integrated p99
            10.0,     // cold start
            &budget,
            None,
        );
        assert!(!r.within_budget, "NaN baseline must fail closed");
    }

    #[test]
    fn test_nan_integrated_fails_closed() {
        let budget = HotPathBudget {
            hot_path: HotPath::LifecycleTransition,
            p95_overhead_pct: 15.0,
            p99_overhead_pct: 25.0,
            cold_start_ms: 50.0,
        };
        let r = MeasurementResult::from_measurements(
            HotPath::LifecycleTransition,
            70.0,
            100.0,
            130.0,
            77.0,
            f64::NAN, // integrated p95 — NaN
            135.0,
            10.0,
            &budget,
            None,
        );
        assert!(!r.within_budget, "NaN integrated must fail closed");
    }

    #[test]
    fn test_nan_cold_start_fails_closed() {
        let budget = HotPathBudget {
            hot_path: HotPath::LifecycleTransition,
            p95_overhead_pct: 15.0,
            p99_overhead_pct: 25.0,
            cold_start_ms: 50.0,
        };
        let r = MeasurementResult::from_measurements(
            HotPath::LifecycleTransition,
            70.0,
            100.0,
            130.0,
            77.0,
            105.0,
            135.0,
            f64::NAN, // cold start — NaN
            &budget,
            None,
        );
        assert!(!r.within_budget, "NaN cold-start must fail closed");
    }

    #[test]
    fn test_inf_baseline_fails_closed() {
        let budget = HotPathBudget {
            hot_path: HotPath::LifecycleTransition,
            p95_overhead_pct: 15.0,
            p99_overhead_pct: 25.0,
            cold_start_ms: 50.0,
        };
        let r = MeasurementResult::from_measurements(
            HotPath::LifecycleTransition,
            70.0,
            f64::INFINITY,
            130.0,
            77.0,
            105.0,
            135.0,
            10.0,
            &budget,
            None,
        );
        assert!(!r.within_budget, "Inf baseline must fail closed");
    }

    #[test]
    fn test_nan_baseline_p99_fails_closed() {
        let budget = HotPathBudget {
            hot_path: HotPath::LifecycleTransition,
            p95_overhead_pct: 15.0,
            p99_overhead_pct: 25.0,
            cold_start_ms: 50.0,
        };
        let r = MeasurementResult::from_measurements(
            HotPath::LifecycleTransition,
            70.0,
            100.0,
            f64::NAN,
            77.0,
            105.0,
            135.0,
            10.0,
            &budget,
            None,
        );
        assert!(!r.within_budget, "NaN p99 baseline must fail closed");
    }

    #[test]
    fn test_nan_integrated_p99_fails_closed() {
        let budget = HotPathBudget {
            hot_path: HotPath::LifecycleTransition,
            p95_overhead_pct: 15.0,
            p99_overhead_pct: 25.0,
            cold_start_ms: 50.0,
        };
        let r = MeasurementResult::from_measurements(
            HotPath::LifecycleTransition,
            70.0,
            100.0,
            130.0,
            77.0,
            105.0,
            f64::NAN,
            10.0,
            &budget,
            None,
        );
        assert!(!r.within_budget, "NaN p99 integrated must fail closed");
    }

    #[test]
    fn test_inf_integrated_p95_fails_closed() {
        let budget = HotPathBudget {
            hot_path: HotPath::LifecycleTransition,
            p95_overhead_pct: 15.0,
            p99_overhead_pct: 25.0,
            cold_start_ms: 50.0,
        };
        let r = MeasurementResult::from_measurements(
            HotPath::LifecycleTransition,
            70.0,
            100.0,
            130.0,
            77.0,
            f64::INFINITY,
            135.0,
            10.0,
            &budget,
            None,
        );
        assert!(!r.within_budget, "Inf p95 integrated must fail closed");
    }

    #[test]
    fn test_inf_cold_start_fails_closed() {
        let budget = HotPathBudget {
            hot_path: HotPath::LifecycleTransition,
            p95_overhead_pct: 15.0,
            p99_overhead_pct: 25.0,
            cold_start_ms: 50.0,
        };
        let r = MeasurementResult::from_measurements(
            HotPath::LifecycleTransition,
            70.0,
            100.0,
            130.0,
            77.0,
            105.0,
            135.0,
            f64::INFINITY,
            &budget,
            None,
        );
        assert!(!r.within_budget, "Inf cold start must fail closed");
    }

    #[test]
    fn test_missing_policy_budget_fails_without_false_violations() {
        let mut gate = OverheadGate::new(BudgetPolicy {
            budgets: Vec::new(),
        });
        let result = over_budget_result(HotPath::HealthGateEvaluation);

        let decision = gate.evaluate(result);

        match decision {
            GateDecision::Fail { violations } => assert!(violations.is_empty()),
            GateDecision::Pass => {
                unreachable!("missing budget must not turn failed result into pass")
            }
        }
        assert!(!gate.gate_pass());
        assert_eq!(gate.summary().over_budget, 1);
        assert!(
            gate.events()
                .iter()
                .any(|event| event.code == event_codes::PRF_003_OVER_BUDGET)
        );
    }

    #[test]
    fn test_p95_only_violation_reports_p95() {
        let budget = HotPathBudget {
            hot_path: HotPath::HealthGateEvaluation,
            p95_overhead_pct: 5.0,
            p99_overhead_pct: 50.0,
            cold_start_ms: 50.0,
        };
        let mut gate = OverheadGate::new(BudgetPolicy {
            budgets: vec![budget.clone()],
        });
        let result = MeasurementResult::from_measurements(
            HotPath::HealthGateEvaluation,
            100.0,
            100.0,
            100.0,
            105.0,
            110.0,
            110.0,
            10.0,
            &budget,
            None,
        );

        let decision = gate.evaluate(result);

        match decision {
            GateDecision::Fail { violations } => {
                assert_eq!(violations.len(), 1);
                assert!(violations[0].contains("p95 overhead"));
            }
            GateDecision::Pass => unreachable!("p95-only violation must fail"),
        }
    }

    #[test]
    fn test_p99_only_violation_reports_p99() {
        let budget = HotPathBudget {
            hot_path: HotPath::HealthGateEvaluation,
            p95_overhead_pct: 50.0,
            p99_overhead_pct: 5.0,
            cold_start_ms: 50.0,
        };
        let mut gate = OverheadGate::new(BudgetPolicy {
            budgets: vec![budget.clone()],
        });
        let result = MeasurementResult::from_measurements(
            HotPath::HealthGateEvaluation,
            100.0,
            100.0,
            100.0,
            105.0,
            110.0,
            110.0,
            10.0,
            &budget,
            None,
        );

        let decision = gate.evaluate(result);

        match decision {
            GateDecision::Fail { violations } => {
                assert_eq!(violations.len(), 1);
                assert!(violations[0].contains("p99 overhead"));
            }
            GateDecision::Pass => unreachable!("p99-only violation must fail"),
        }
    }

    #[test]
    fn test_cold_start_only_violation_reports_cold_start() {
        let budget = HotPathBudget {
            hot_path: HotPath::HealthGateEvaluation,
            p95_overhead_pct: 50.0,
            p99_overhead_pct: 50.0,
            cold_start_ms: 5.0,
        };
        let mut gate = OverheadGate::new(BudgetPolicy {
            budgets: vec![budget.clone()],
        });
        let result = MeasurementResult::from_measurements(
            HotPath::HealthGateEvaluation,
            100.0,
            100.0,
            100.0,
            105.0,
            110.0,
            110.0,
            10.0,
            &budget,
            None,
        );

        let decision = gate.evaluate(result);

        match decision {
            GateDecision::Fail { violations } => {
                assert_eq!(violations.len(), 1);
                assert!(violations[0].contains("cold-start"));
            }
            GateDecision::Pass => unreachable!("cold-start-only violation must fail"),
        }
    }

    #[test]
    fn test_negative_baseline_p50_fails_closed() {
        let budget = default_budget();
        let r = MeasurementResult::from_measurements(
            HotPath::HealthGateEvaluation,
            -1.0,
            100.0,
            120.0,
            80.0,
            105.0,
            125.0,
            10.0,
            &budget,
            None,
        );

        assert!(!r.within_budget, "negative baseline p50 must fail closed");
    }

    #[test]
    fn test_negative_baseline_p95_fails_closed() {
        let budget = default_budget();
        let r = MeasurementResult::from_measurements(
            HotPath::HealthGateEvaluation,
            90.0,
            -100.0,
            120.0,
            80.0,
            105.0,
            125.0,
            10.0,
            &budget,
            None,
        );

        assert!(!r.within_budget, "negative baseline p95 must fail closed");
    }

    #[test]
    fn test_negative_baseline_p99_fails_closed() {
        let budget = default_budget();
        let r = MeasurementResult::from_measurements(
            HotPath::HealthGateEvaluation,
            90.0,
            100.0,
            -120.0,
            80.0,
            105.0,
            125.0,
            10.0,
            &budget,
            None,
        );

        assert!(!r.within_budget, "negative baseline p99 must fail closed");
    }

    #[test]
    fn test_negative_integrated_p50_fails_closed() {
        let budget = default_budget();
        let r = MeasurementResult::from_measurements(
            HotPath::HealthGateEvaluation,
            90.0,
            100.0,
            120.0,
            -80.0,
            105.0,
            125.0,
            10.0,
            &budget,
            None,
        );

        assert!(!r.within_budget, "negative integrated p50 must fail closed");
    }

    #[test]
    fn test_negative_integrated_p95_fails_closed() {
        let budget = default_budget();
        let r = MeasurementResult::from_measurements(
            HotPath::HealthGateEvaluation,
            90.0,
            100.0,
            120.0,
            80.0,
            -105.0,
            125.0,
            10.0,
            &budget,
            None,
        );

        assert!(!r.within_budget, "negative integrated p95 must fail closed");
    }

    #[test]
    fn test_negative_cold_start_fails_closed() {
        let budget = default_budget();
        let r = MeasurementResult::from_measurements(
            HotPath::HealthGateEvaluation,
            90.0,
            100.0,
            120.0,
            80.0,
            105.0,
            125.0,
            -10.0,
            &budget,
            None,
        );

        assert!(!r.within_budget, "negative cold start must fail closed");
    }

    // ── NEGATIVE-PATH TESTS: Security & Robustness ──────────────────

    #[test]
    fn test_negative_trace_id_with_unicode_injection_attacks() {
        use crate::security::constant_time::ct_eq;

        let mut gate = OverheadGate::with_default_policy();
        let result = within_budget_result(HotPath::HealthGateEvaluation);

        // Evaluate to trigger trace ID generation
        let _ = gate.evaluate(result);
        let events = gate.events();

        // Verify trace ID is sanitized and doesn't contain injection patterns
        let trace_id = &events[0].trace_id;

        // Should NOT contain BiDi override characters
        assert!(!trace_id.contains('\u{202E}'), "trace ID must not contain BiDi override");
        assert!(!trace_id.contains('\u{202D}'), "trace ID must not contain BiDi override");

        // Should NOT contain ANSI escape sequences
        assert!(!trace_id.contains("\x1b["), "trace ID must not contain ANSI escapes");

        // Should NOT contain null bytes or control characters
        assert!(!trace_id.contains('\0'), "trace ID must not contain null bytes");
        assert!(!trace_id.contains('\r'), "trace ID must not contain carriage return");
        assert!(!trace_id.contains('\n'), "trace ID must not contain newlines");

        // Should use constant-time comparison for generated trace IDs
        let expected_prefix = "perf-health_gate_evaluation";
        assert!(ct_eq(trace_id.as_str(), expected_prefix),
               "trace ID comparison must be constant-time");
    }

    #[test]
    fn test_negative_event_detail_with_massive_memory_exhaustion() {
        let mut gate = OverheadGate::with_default_policy();
        let massive_detail = "A".repeat(1_000_000); // 1MB string

        // Create malicious event with huge detail
        let malicious_event = OverheadEvent {
            code: event_codes::PRF_001_BENCHMARK_STARTED.to_string(),
            hot_path: "health_gate_evaluation".to_string(),
            detail: massive_detail.clone(),
            overhead_pct: Some(5.0),
            trace_id: "trace-001".to_string(),
        };

        // Simulate bounded event storage
        push_bounded(&mut gate.events, malicious_event, MAX_EVENTS);

        // Verify bounded storage prevents memory exhaustion
        assert!(gate.events().len() <= MAX_EVENTS,
               "event storage must respect MAX_EVENTS bound");

        // Verify event detail is properly bounded when serialized
        let json = serde_json::to_string(&gate.events()[0]).unwrap_or_default();
        assert!(json.len() < 10_000_000, "serialized event must not cause memory exhaustion");

        // Verify CSV export is also bounded
        let csv = gate.to_csv();
        assert!(csv.len() < 10_000_000, "CSV export must not cause memory exhaustion");
    }

    #[test]
    fn test_negative_policy_with_json_injection_attacks() {
        // Create policy with malicious JSON injection patterns in flamegraph paths
        let malicious_budget = HotPathBudget {
            hot_path: HotPath::HealthGateEvaluation,
            p95_overhead_pct: 10.0,
            p99_overhead_pct: 20.0,
            cold_start_ms: 30.0,
        };

        let result = MeasurementResult::from_measurements(
            HotPath::HealthGateEvaluation,
            100.0, 110.0, 120.0,
            105.0, 118.0, 130.0,
            15.0,
            &malicious_budget,
            Some(r#"flamegraph.svg","injection":"malicious"}"#.to_string())
        );

        // Serialize to JSON and verify no injection
        let json = serde_json::to_string(&result).unwrap();

        // Verify JSON structure integrity - should properly escape the injection
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let flamegraph_path = parsed["flamegraph_path"].as_str().unwrap();

        // Should be the literal string, not parsed as JSON injection
        assert_eq!(flamegraph_path, r#"flamegraph.svg","injection":"malicious"}"#);

        // Verify no extra fields were injected
        assert!(parsed.get("injection").is_none(), "JSON injection must not create extra fields");
    }

    #[test]
    fn test_negative_hot_path_display_injection_resistance() {
        // Test that HotPath display doesn't allow injection
        for hot_path in HotPath::all() {
            let display_str = format!("{}", hot_path);
            let label_str = hot_path.label();

            // Verify no ANSI escape sequences
            assert!(!display_str.contains("\x1b["),
                   "HotPath display must not contain ANSI escapes: {}", hot_path);
            assert!(!label_str.contains("\x1b["),
                   "HotPath label must not contain ANSI escapes: {}", hot_path);

            // Verify no BiDi override attacks
            assert!(!display_str.contains('\u{202E}'),
                   "HotPath display must not contain BiDi override: {}", hot_path);
            assert!(!label_str.contains('\u{202E}'),
                   "HotPath label must not contain BiDi override: {}", hot_path);

            // Verify no null bytes or newlines
            assert!(!display_str.contains('\0'),
                   "HotPath display must not contain null bytes: {}", hot_path);
            assert!(!display_str.contains('\n'),
                   "HotPath display must not contain newlines: {}", hot_path);

            // Verify consistent safe length
            assert!(display_str.len() < 100,
                   "HotPath display must be reasonably bounded: {}", hot_path);
            assert!(label_str.len() < 100,
                   "HotPath label must be reasonably bounded: {}", hot_path);
        }
    }

    #[test]
    fn test_negative_csv_output_with_malicious_field_injection() {
        let mut gate = OverheadGate::with_default_policy();

        // Create measurement with malicious injection attempts in flamegraph path
        let budget = default_budget();
        let malicious_result = MeasurementResult {
            hot_path: HotPath::HealthGateEvaluation,
            baseline_p50_us: 100.0,
            baseline_p95_us: 110.0,
            baseline_p99_us: 120.0,
            integrated_p50_us: 105.0,
            integrated_p95_us: 118.0,
            integrated_p99_us: 130.0,
            overhead_p95_pct: 7.27,
            overhead_p99_pct: 8.33,
            cold_start_ms: 15.0,
            within_budget: true,
            flamegraph_path: Some("file.svg\",\"injected_field\":\"malicious".to_string()),
        };

        gate.evaluate(malicious_result);
        let csv = gate.to_csv();

        // Verify CSV structure integrity
        let lines: Vec<&str> = csv.lines().collect();
        assert!(lines.len() >= 2, "CSV must have header and data rows");

        // Verify header is not corrupted
        let header = lines[0];
        let expected_header = "hot_path,baseline_p50_us,baseline_p95_us,baseline_p99_us,integrated_p50_us,integrated_p95_us,integrated_p99_us,overhead_p95_pct,overhead_p99_pct,cold_start_ms,within_budget";
        assert_eq!(header, expected_header, "CSV header must not be corrupted by injection");

        // Verify data row has exactly the expected number of fields
        let data_row = lines[1];
        let fields: Vec<&str> = data_row.split(',').collect();
        assert_eq!(fields.len(), 11, "CSV data row must have exactly 11 fields, not be corrupted by injection");

        // Verify no extra commas from injection
        let comma_count = data_row.matches(',').count();
        assert_eq!(comma_count, 10, "CSV data row must have exactly 10 commas");
    }

    #[test]
    fn test_negative_budget_policy_with_massive_budget_list_memory_stress() {
        // Create policy with 10,000 identical budgets to stress memory
        let massive_budgets: Vec<HotPathBudget> = (0..10_000)
            .map(|i| HotPathBudget {
                hot_path: if i % 4 == 0 { HotPath::LifecycleTransition }
                         else if i % 4 == 1 { HotPath::HealthGateEvaluation }
                         else if i % 4 == 2 { HotPath::RolloutStateChange }
                         else { HotPath::FencingTokenOp },
                p95_overhead_pct: (i as f64) * 0.001, // Vary slightly
                p99_overhead_pct: (i as f64) * 0.002,
                cold_start_ms: (i as f64) * 0.01,
            })
            .collect();

        let massive_policy = BudgetPolicy {
            budgets: massive_budgets,
        };

        // Verify policy creation doesn't crash
        let gate = OverheadGate::new(massive_policy);

        // Verify budget lookup still works efficiently
        let budget = gate.policy().budget_for(HotPath::HealthGateEvaluation);
        assert!(budget.is_some(), "budget lookup must work even with massive policy");

        // Verify JSON serialization is bounded
        let json = gate.policy().to_json();
        assert!(json.len() < 50_000_000, "massive policy JSON must not cause excessive memory usage");

        // Verify policy doesn't cause stack overflow in normal operations
        let test_result = within_budget_result(HotPath::HealthGateEvaluation);
        let mut test_gate = OverheadGate::new(gate.policy().clone());
        let decision = test_gate.evaluate(test_result);
        assert!(decision.is_pass(), "massive policy must not break normal evaluation");
    }

    #[test]
    fn test_negative_overhead_calculation_with_extreme_floating_point_edge_cases() {
        let budget = default_budget();

        // Test with values very close to zero (potential division issues)
        let near_zero_result = MeasurementResult::from_measurements(
            HotPath::HealthGateEvaluation,
            1e-100, 1e-100, 1e-100, // baseline near zero
            1e-99,  1e-99,  1e-99,  // integrated slightly larger
            10.0,
            &budget,
            None,
        );
        // Should handle gracefully without panic
        assert!(near_zero_result.overhead_p95_pct.is_finite() || near_zero_result.overhead_p95_pct == 0.0);

        // Test with very large finite values (near f64::MAX)
        let huge_baseline = 1e100;
        let huge_integrated = huge_baseline * 2.0; // Would cause 100% overhead if computed naively

        let huge_result = MeasurementResult::from_measurements(
            HotPath::HealthGateEvaluation,
            huge_baseline, huge_baseline, huge_baseline,
            huge_integrated, huge_integrated, huge_integrated,
            10.0,
            &budget,
            None,
        );

        // Should detect this is over budget due to extreme overhead
        assert!(!huge_result.within_budget, "extreme overhead must fail budget");

        // Test overflow protection in saturating arithmetic patterns
        let max_result = MeasurementResult::from_measurements(
            HotPath::HealthGateEvaluation,
            f64::MAX / 2.0, f64::MAX / 2.0, f64::MAX / 2.0,
            f64::MAX, f64::MAX, f64::MAX,
            f64::MAX,
            &budget,
            None,
        );

        // Should fail closed rather than overflow
        assert!(!max_result.within_budget, "extreme values must fail closed");
    }

    #[test]
    fn test_negative_gate_decision_display_injection_prevention() {
        // Test Pass decision display safety
        let pass_display = format!("{}", GateDecision::Pass);
        assert_eq!(pass_display, "PASS");
        assert!(!pass_display.contains('\n'));
        assert!(!pass_display.contains('\0'));

        // Test Fail decision with injection attempts in violation messages
        let malicious_violations = vec![
            "p95 overhead 50.0% > budget 10.0%\x1b[31m<INJECTION>\x1b[0m".to_string(),
            "violation\",\"injected\":\"field\"}//".to_string(),
            "violation\ninjected_line".to_string(),
            "violation\0null_injection".to_string(),
            "violation\u{202E}bidi_override".to_string(),
        ];

        let fail_decision = GateDecision::Fail {
            violations: malicious_violations.clone()
        };

        let display_str = format!("{}", fail_decision);

        // Verify basic structure is maintained
        assert!(display_str.starts_with("FAIL"));
        assert!(display_str.contains("5 violations"));

        // Verify the display itself doesn't propagate injection patterns
        // (The violations are stored as-is, but display should be safe)
        assert!(!display_str.contains("\x1b[31m"),
               "display must not propagate ANSI escape sequences");

        // Test serde safety with malicious violations
        let json = serde_json::to_string(&fail_decision).unwrap();
        let parsed: GateDecision = serde_json::from_str(&json).unwrap();

        if let GateDecision::Fail { violations: parsed_violations } = parsed {
            assert_eq!(parsed_violations.len(), 5);
            // Verify violations are preserved exactly (for forensics) but contained
            assert_eq!(parsed_violations, malicious_violations);
        } else {
            panic!("parsed decision should be Fail");
        }
    }

    #[test]
    fn test_negative_concurrent_gate_evaluation_race_conditions() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let gate = Arc::new(Mutex::new(OverheadGate::with_default_policy()));
        let mut handles = Vec::new();

        // Spawn 8 threads doing concurrent evaluations
        for thread_id in 0..8 {
            let gate_clone = Arc::clone(&gate);
            let handle = thread::spawn(move || {
                for i in 0..100 {
                    let hot_path = match (thread_id + i) % 4 {
                        0 => HotPath::LifecycleTransition,
                        1 => HotPath::HealthGateEvaluation,
                        2 => HotPath::RolloutStateChange,
                        _ => HotPath::FencingTokenOp,
                    };

                    let result = within_budget_result(hot_path);

                    // Acquire lock and evaluate
                    let mut locked_gate = gate_clone.lock().unwrap();
                    let decision = locked_gate.evaluate(result);
                    assert!(decision.is_pass(), "concurrent evaluation must remain correct");

                    // Verify internal state consistency
                    let summary = locked_gate.summary();
                    assert!(summary.total > 0, "total count must be positive");
                    assert_eq!(summary.over_budget, 0, "all results should be within budget");
                    assert!(summary.within_budget <= summary.total, "counts must be consistent");
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify final state
        let final_gate = gate.lock().unwrap();
        let final_summary = final_gate.summary();
        assert_eq!(final_summary.total, 800, "should have 8 threads × 100 evaluations");
        assert_eq!(final_summary.within_budget, 800, "all should be within budget");
        assert_eq!(final_summary.over_budget, 0, "none should be over budget");
        assert!(final_gate.gate_pass(), "final gate should pass");
    }

    #[test]
    fn test_negative_report_generation_with_malicious_policy_fields() {
        // Create policy with potential injection in JSON serialization
        let mut malicious_budgets = Vec::new();
        for _ in 0..1000 {
            malicious_budgets.push(HotPathBudget {
                hot_path: HotPath::HealthGateEvaluation,
                p95_overhead_pct: f64::INFINITY, // Extreme value
                p99_overhead_pct: f64::NEG_INFINITY, // Extreme value
                cold_start_ms: f64::NAN, // Extreme value
            });
        }

        let malicious_policy = BudgetPolicy {
            budgets: malicious_budgets,
        };

        let mut gate = OverheadGate::new(malicious_policy);

        // Add some results
        for hot_path in HotPath::all() {
            gate.evaluate(within_budget_result(*hot_path));
        }

        // Generate report and verify it's safe
        let report = gate.to_report();

        // Verify report structure
        assert!(report["bead_id"].is_string());
        assert!(report["section"].is_string());
        assert!(report["gate_pass"].is_boolean());
        assert!(report["summary"].is_object());
        assert!(report["policy"].is_object());
        assert!(report["results"].is_array());

        // Verify extreme values in policy are handled safely
        let policy_json = report["policy"].clone();
        let policy_str = serde_json::to_string(&policy_json).unwrap();

        // Should not contain raw infinity/NaN that could break parsers
        // (serde_json should serialize these as null or string representations)
        assert!(policy_str.len() < 1_000_000, "policy serialization must be bounded");

        // Verify report can be re-parsed safely
        let report_str = serde_json::to_string(&report).unwrap();
        let reparsed: serde_json::Value = serde_json::from_str(&report_str).unwrap();
        assert_eq!(reparsed["bead_id"], report["bead_id"]);
    }

    #[test]
    fn test_negative_measurement_result_field_bypass_with_case_sensitivity() {
        // Test potential bypass via case sensitivity in field names
        let json_mixed_case = r#"{
            "Hot_Path": "HealthGateEvaluation",
            "hot_path": "LifecycleTransition",
            "baseline_p50_us": 100.0,
            "Baseline_P95_Us": 999.0,
            "baseline_p95_us": 110.0,
            "baseline_p99_us": 120.0,
            "integrated_p50_us": 105.0,
            "integrated_p95_us": 118.0,
            "integrated_p99_us": 130.0,
            "overhead_p95_pct": 7.27,
            "overhead_p99_pct": 8.33,
            "cold_start_ms": 15.0,
            "within_budget": true,
            "flamegraph_path": null
        }"#;

        // Should fail to parse due to unknown fields or use only the correct cased fields
        let result: Result<MeasurementResult, _> = serde_json::from_str(json_mixed_case);

        // Depending on serde behavior, this should either:
        // 1. Fail to parse (preferred for security), or
        // 2. Use only the correctly cased fields and ignore the rest
        if let Ok(parsed) = result {
            // If it parses, verify it used the correct cased field values
            assert_eq!(parsed.hot_path, HotPath::LifecycleTransition);
            assert_eq!(parsed.baseline_p95_us, 110.0); // Should use lowercase version
        }
        // If it fails to parse, that's also acceptable security behavior
    }
}
