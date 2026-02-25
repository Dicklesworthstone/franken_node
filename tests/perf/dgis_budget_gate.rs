//! bd-38yt: DGIS performance budget and claim-gate contract tests.
//!
//! This file defines deterministic p95/p99 budget contracts for the major DGIS
//! computation classes and verifies release-gate behavior:
//! - Graph ingestion
//! - Metric computation
//! - Contagion simulation
//! - Economic ranking
//!
//! Event codes:
//! - `DGIS-PERF-001` gate start
//! - `DGIS-PERF-002` gate allow
//! - `DGIS-PERF-003` latency budget violation
//! - `DGIS-PERF-004` signed evidence completeness violation
//! - `DGIS-PERF-005` degradation signal emitted

use serde::{Deserialize, Serialize};
use std::fmt;

pub mod event_codes {
    pub const DGIS_PERF_001: &str = "DGIS-PERF-001";
    pub const DGIS_PERF_002: &str = "DGIS-PERF-002";
    pub const DGIS_PERF_003: &str = "DGIS-PERF-003";
    pub const DGIS_PERF_004: &str = "DGIS-PERF-004";
    pub const DGIS_PERF_005: &str = "DGIS-PERF-005";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DgisComputation {
    GraphIngestion,
    MetricComputation,
    ContagionSimulation,
    EconomicRanking,
}

impl DgisComputation {
    pub fn label(&self) -> &'static str {
        match self {
            Self::GraphIngestion => "graph_ingestion",
            Self::MetricComputation => "metric_computation",
            Self::ContagionSimulation => "contagion_simulation",
            Self::EconomicRanking => "economic_ranking",
        }
    }
}

impl fmt::Display for DgisComputation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScaleProfile {
    pub nodes: u64,
    pub edges: u64,
    pub max_articulation_points: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DgisBudget {
    pub computation: DgisComputation,
    pub budget_p95_ms: f64,
    pub budget_p99_ms: f64,
    pub target_scale: ScaleProfile,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DgisMeasurement {
    pub computation: DgisComputation,
    pub measured_p95_ms: f64,
    pub measured_p99_ms: f64,
    pub signed_evidence_present: u32,
    pub required_signed_evidence: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetOutcome {
    Pass,
    Degraded { code: &'static str, reason: String },
    Fail { code: &'static str, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateSummary {
    pub total: usize,
    pub pass: usize,
    pub degraded: usize,
    pub fail: usize,
    pub release_decision: &'static str,
}

pub fn default_budgets() -> Vec<DgisBudget> {
    vec![
        DgisBudget {
            computation: DgisComputation::GraphIngestion,
            budget_p95_ms: 45.0,
            budget_p99_ms: 60.0,
            target_scale: ScaleProfile {
                nodes: 25_000,
                edges: 180_000,
                max_articulation_points: 320,
            },
        },
        DgisBudget {
            computation: DgisComputation::MetricComputation,
            budget_p95_ms: 70.0,
            budget_p99_ms: 95.0,
            target_scale: ScaleProfile {
                nodes: 25_000,
                edges: 180_000,
                max_articulation_points: 320,
            },
        },
        DgisBudget {
            computation: DgisComputation::ContagionSimulation,
            budget_p95_ms: 90.0,
            budget_p99_ms: 130.0,
            target_scale: ScaleProfile {
                nodes: 25_000,
                edges: 180_000,
                max_articulation_points: 320,
            },
        },
        DgisBudget {
            computation: DgisComputation::EconomicRanking,
            budget_p95_ms: 55.0,
            budget_p99_ms: 75.0,
            target_scale: ScaleProfile {
                nodes: 25_000,
                edges: 180_000,
                max_articulation_points: 320,
            },
        },
    ]
}

pub fn evaluate_budget(budget: &DgisBudget, measurement: &DgisMeasurement) -> BudgetOutcome {
    if budget.computation != measurement.computation {
        return BudgetOutcome::Fail {
            code: event_codes::DGIS_PERF_004,
            reason: "measurement computation does not match budget target".to_string(),
        };
    }

    if measurement.signed_evidence_present < measurement.required_signed_evidence {
        return BudgetOutcome::Fail {
            code: event_codes::DGIS_PERF_004,
            reason: format!(
                "signed evidence shortfall: present={} required={}",
                measurement.signed_evidence_present, measurement.required_signed_evidence
            ),
        };
    }

    if measurement.measured_p99_ms > budget.budget_p99_ms {
        return BudgetOutcome::Fail {
            code: event_codes::DGIS_PERF_003,
            reason: format!(
                "p99 {:.3}ms exceeded budget {:.3}ms for {}",
                measurement.measured_p99_ms, budget.budget_p99_ms, budget.computation
            ),
        };
    }

    if measurement.measured_p95_ms > budget.budget_p95_ms {
        return BudgetOutcome::Degraded {
            code: event_codes::DGIS_PERF_005,
            reason: format!(
                "p95 {:.3}ms exceeded budget {:.3}ms for {}",
                measurement.measured_p95_ms, budget.budget_p95_ms, budget.computation
            ),
        };
    }

    BudgetOutcome::Pass
}

pub fn summarize(outcomes: &[BudgetOutcome]) -> GateSummary {
    let mut pass = 0usize;
    let mut degraded = 0usize;
    let mut fail = 0usize;

    for outcome in outcomes {
        match outcome {
            BudgetOutcome::Pass => pass += 1,
            BudgetOutcome::Degraded { .. } => degraded += 1,
            BudgetOutcome::Fail { .. } => fail += 1,
        }
    }

    let release_decision = if fail == 0 && degraded == 0 {
        "allow"
    } else {
        "block"
    };

    GateSummary {
        total: outcomes.len(),
        pass,
        degraded,
        fail,
        release_decision,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nominal_measurement(computation: DgisComputation) -> DgisMeasurement {
        match computation {
            DgisComputation::GraphIngestion => DgisMeasurement {
                computation,
                measured_p95_ms: 31.0,
                measured_p99_ms: 44.0,
                signed_evidence_present: 1,
                required_signed_evidence: 1,
            },
            DgisComputation::MetricComputation => DgisMeasurement {
                computation,
                measured_p95_ms: 52.0,
                measured_p99_ms: 76.0,
                signed_evidence_present: 1,
                required_signed_evidence: 1,
            },
            DgisComputation::ContagionSimulation => DgisMeasurement {
                computation,
                measured_p95_ms: 68.0,
                measured_p99_ms: 98.0,
                signed_evidence_present: 1,
                required_signed_evidence: 1,
            },
            DgisComputation::EconomicRanking => DgisMeasurement {
                computation,
                measured_p95_ms: 40.0,
                measured_p99_ms: 57.0,
                signed_evidence_present: 2,
                required_signed_evidence: 2,
            },
        }
    }

    #[test]
    fn default_budgets_cover_all_required_computations() {
        let budgets = default_budgets();
        assert_eq!(budgets.len(), 4);
        assert!(budgets.iter().any(|b| b.computation == DgisComputation::GraphIngestion));
        assert!(budgets.iter().any(|b| b.computation == DgisComputation::MetricComputation));
        assert!(budgets.iter().any(|b| b.computation == DgisComputation::ContagionSimulation));
        assert!(budgets.iter().any(|b| b.computation == DgisComputation::EconomicRanking));
        for budget in budgets {
            assert!(budget.budget_p95_ms > 0.0);
            assert!(budget.budget_p99_ms >= budget.budget_p95_ms);
            assert!(budget.target_scale.nodes > 0);
            assert!(budget.target_scale.edges > 0);
        }
    }

    #[test]
    fn within_budget_measurement_passes() {
        let budget = default_budgets()
            .into_iter()
            .find(|b| b.computation == DgisComputation::GraphIngestion)
            .expect("graph ingestion budget missing");
        let measurement = nominal_measurement(DgisComputation::GraphIngestion);
        assert_eq!(evaluate_budget(&budget, &measurement), BudgetOutcome::Pass);
    }

    #[test]
    fn p95_breach_emits_degradation_signal() {
        let budget = default_budgets()
            .into_iter()
            .find(|b| b.computation == DgisComputation::MetricComputation)
            .expect("metric budget missing");
        let mut measurement = nominal_measurement(DgisComputation::MetricComputation);
        measurement.measured_p95_ms = budget.budget_p95_ms + 5.0;
        let outcome = evaluate_budget(&budget, &measurement);
        match outcome {
            BudgetOutcome::Degraded { code, .. } => assert_eq!(code, event_codes::DGIS_PERF_005),
            _ => panic!("expected degraded outcome"),
        }
    }

    #[test]
    fn p99_breach_fails_gate() {
        let budget = default_budgets()
            .into_iter()
            .find(|b| b.computation == DgisComputation::ContagionSimulation)
            .expect("contagion budget missing");
        let mut measurement = nominal_measurement(DgisComputation::ContagionSimulation);
        measurement.measured_p99_ms = budget.budget_p99_ms + 1.0;
        let outcome = evaluate_budget(&budget, &measurement);
        match outcome {
            BudgetOutcome::Fail { code, .. } => assert_eq!(code, event_codes::DGIS_PERF_003),
            _ => panic!("expected failure outcome"),
        }
    }

    #[test]
    fn signed_evidence_shortfall_fails_gate() {
        let budget = default_budgets()
            .into_iter()
            .find(|b| b.computation == DgisComputation::EconomicRanking)
            .expect("economic budget missing");
        let mut measurement = nominal_measurement(DgisComputation::EconomicRanking);
        measurement.signed_evidence_present = 1;
        let outcome = evaluate_budget(&budget, &measurement);
        match outcome {
            BudgetOutcome::Fail { code, .. } => assert_eq!(code, event_codes::DGIS_PERF_004),
            _ => panic!("expected failure outcome"),
        }
    }

    #[test]
    fn summary_blocks_when_any_violation_present() {
        let summary = summarize(&[
            BudgetOutcome::Pass,
            BudgetOutcome::Degraded {
                code: event_codes::DGIS_PERF_005,
                reason: "p95 breach".to_string(),
            },
            BudgetOutcome::Pass,
            BudgetOutcome::Pass,
        ]);
        assert_eq!(summary.total, 4);
        assert_eq!(summary.degraded, 1);
        assert_eq!(summary.fail, 0);
        assert_eq!(summary.release_decision, "block");
    }

    #[test]
    fn summary_allows_when_all_pass() {
        let summary = summarize(&[
            BudgetOutcome::Pass,
            BudgetOutcome::Pass,
            BudgetOutcome::Pass,
            BudgetOutcome::Pass,
        ]);
        assert_eq!(summary.total, 4);
        assert_eq!(summary.pass, 4);
        assert_eq!(summary.release_decision, "allow");
    }
}
