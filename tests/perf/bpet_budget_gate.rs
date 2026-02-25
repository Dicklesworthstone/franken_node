//! bd-3v9l: BPET performance budget and release-claim gate contract tests.
//!
//! This file defines deterministic budget contracts for predictive
//! pre-compromise trajectory assertions:
//! - Trajectory scoring latency
//! - Drift/regime analysis latency
//! - Lineage persistence storage overhead
//! - Claim package compilation latency
//!
//! Event codes:
//! - `BPET-PERF-001` gate start
//! - `BPET-PERF-002` gate allow
//! - `BPET-PERF-003` latency/storage budget violation
//! - `BPET-PERF-004` calibration/provenance completeness violation
//! - `BPET-PERF-005` degradation signal emitted

use serde::{Deserialize, Serialize};
use std::fmt;

pub mod event_codes {
    pub const BPET_PERF_001: &str = "BPET-PERF-001";
    pub const BPET_PERF_002: &str = "BPET-PERF-002";
    pub const BPET_PERF_003: &str = "BPET-PERF-003";
    pub const BPET_PERF_004: &str = "BPET-PERF-004";
    pub const BPET_PERF_005: &str = "BPET-PERF-005";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BpetComputation {
    TrajectoryScoring,
    DriftAnalysis,
    LineagePersistence,
    ClaimCompilation,
}

impl BpetComputation {
    pub fn label(&self) -> &'static str {
        match self {
            Self::TrajectoryScoring => "trajectory_scoring",
            Self::DriftAnalysis => "drift_analysis",
            Self::LineagePersistence => "lineage_persistence",
            Self::ClaimCompilation => "claim_compilation",
        }
    }
}

impl fmt::Display for BpetComputation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScaleProfile {
    pub phenotypes: u64,
    pub trajectories: u64,
    pub history_days: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BpetBudget {
    pub computation: BpetComputation,
    pub budget_p95_ms: f64,
    pub budget_p99_ms: f64,
    pub budget_storage_mb: f64,
    pub target_scale: ScaleProfile,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BpetMeasurement {
    pub computation: BpetComputation,
    pub measured_p95_ms: f64,
    pub measured_p99_ms: f64,
    pub measured_storage_mb: f64,
    pub calibration_artifacts_present: u32,
    pub required_calibration_artifacts: u32,
    pub signed_provenance_present: u32,
    pub required_signed_provenance: u32,
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

pub fn default_budgets() -> Vec<BpetBudget> {
    vec![
        BpetBudget {
            computation: BpetComputation::TrajectoryScoring,
            budget_p95_ms: 40.0,
            budget_p99_ms: 58.0,
            budget_storage_mb: 220.0,
            target_scale: ScaleProfile {
                phenotypes: 12_000,
                trajectories: 320_000,
                history_days: 365,
            },
        },
        BpetBudget {
            computation: BpetComputation::DriftAnalysis,
            budget_p95_ms: 65.0,
            budget_p99_ms: 92.0,
            budget_storage_mb: 260.0,
            target_scale: ScaleProfile {
                phenotypes: 12_000,
                trajectories: 320_000,
                history_days: 365,
            },
        },
        BpetBudget {
            computation: BpetComputation::LineagePersistence,
            budget_p95_ms: 55.0,
            budget_p99_ms: 82.0,
            budget_storage_mb: 310.0,
            target_scale: ScaleProfile {
                phenotypes: 12_000,
                trajectories: 320_000,
                history_days: 365,
            },
        },
        BpetBudget {
            computation: BpetComputation::ClaimCompilation,
            budget_p95_ms: 48.0,
            budget_p99_ms: 70.0,
            budget_storage_mb: 240.0,
            target_scale: ScaleProfile {
                phenotypes: 12_000,
                trajectories: 320_000,
                history_days: 365,
            },
        },
    ]
}

pub fn evaluate_budget(budget: &BpetBudget, measurement: &BpetMeasurement) -> BudgetOutcome {
    if budget.computation != measurement.computation {
        return BudgetOutcome::Fail {
            code: event_codes::BPET_PERF_004,
            reason: "measurement computation does not match budget target".to_string(),
        };
    }

    if measurement.calibration_artifacts_present < measurement.required_calibration_artifacts {
        return BudgetOutcome::Fail {
            code: event_codes::BPET_PERF_004,
            reason: format!(
                "calibration artifact shortfall: present={} required={}",
                measurement.calibration_artifacts_present, measurement.required_calibration_artifacts
            ),
        };
    }

    if measurement.signed_provenance_present < measurement.required_signed_provenance {
        return BudgetOutcome::Fail {
            code: event_codes::BPET_PERF_004,
            reason: format!(
                "signed provenance shortfall: present={} required={}",
                measurement.signed_provenance_present, measurement.required_signed_provenance
            ),
        };
    }

    if measurement.measured_p99_ms > budget.budget_p99_ms
        || measurement.measured_storage_mb > budget.budget_storage_mb
    {
        return BudgetOutcome::Fail {
            code: event_codes::BPET_PERF_003,
            reason: format!(
                "budget exceeded for {} (p99={:.3}/{:.3}ms storage={:.1}/{:.1}MB)",
                budget.computation,
                measurement.measured_p99_ms,
                budget.budget_p99_ms,
                measurement.measured_storage_mb,
                budget.budget_storage_mb
            ),
        };
    }

    if measurement.measured_p95_ms > budget.budget_p95_ms {
        return BudgetOutcome::Degraded {
            code: event_codes::BPET_PERF_005,
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

    fn nominal_measurement(computation: BpetComputation) -> BpetMeasurement {
        match computation {
            BpetComputation::TrajectoryScoring => BpetMeasurement {
                computation,
                measured_p95_ms: 29.0,
                measured_p99_ms: 43.0,
                measured_storage_mb: 180.0,
                calibration_artifacts_present: 1,
                required_calibration_artifacts: 1,
                signed_provenance_present: 1,
                required_signed_provenance: 1,
            },
            BpetComputation::DriftAnalysis => BpetMeasurement {
                computation,
                measured_p95_ms: 49.0,
                measured_p99_ms: 71.0,
                measured_storage_mb: 210.0,
                calibration_artifacts_present: 1,
                required_calibration_artifacts: 1,
                signed_provenance_present: 1,
                required_signed_provenance: 1,
            },
            BpetComputation::LineagePersistence => BpetMeasurement {
                computation,
                measured_p95_ms: 41.0,
                measured_p99_ms: 63.0,
                measured_storage_mb: 260.0,
                calibration_artifacts_present: 1,
                required_calibration_artifacts: 1,
                signed_provenance_present: 1,
                required_signed_provenance: 1,
            },
            BpetComputation::ClaimCompilation => BpetMeasurement {
                computation,
                measured_p95_ms: 33.0,
                measured_p99_ms: 51.0,
                measured_storage_mb: 190.0,
                calibration_artifacts_present: 2,
                required_calibration_artifacts: 2,
                signed_provenance_present: 2,
                required_signed_provenance: 2,
            },
        }
    }

    #[test]
    fn default_budgets_cover_all_required_computations() {
        let budgets = default_budgets();
        assert_eq!(budgets.len(), 4);
        assert!(budgets
            .iter()
            .any(|b| b.computation == BpetComputation::TrajectoryScoring));
        assert!(budgets
            .iter()
            .any(|b| b.computation == BpetComputation::DriftAnalysis));
        assert!(budgets
            .iter()
            .any(|b| b.computation == BpetComputation::LineagePersistence));
        assert!(budgets
            .iter()
            .any(|b| b.computation == BpetComputation::ClaimCompilation));

        for budget in budgets {
            assert!(budget.budget_p95_ms > 0.0);
            assert!(budget.budget_p99_ms >= budget.budget_p95_ms);
            assert!(budget.budget_storage_mb > 0.0);
            assert!(budget.target_scale.phenotypes > 0);
            assert!(budget.target_scale.trajectories > 0);
            assert!(budget.target_scale.history_days > 0);
        }
    }

    #[test]
    fn within_budget_measurement_passes() {
        let budget = default_budgets()
            .into_iter()
            .find(|b| b.computation == BpetComputation::TrajectoryScoring)
            .expect("trajectory budget missing");
        let measurement = nominal_measurement(BpetComputation::TrajectoryScoring);
        assert_eq!(evaluate_budget(&budget, &measurement), BudgetOutcome::Pass);
    }

    #[test]
    fn p95_breach_emits_degradation_signal() {
        let budget = default_budgets()
            .into_iter()
            .find(|b| b.computation == BpetComputation::DriftAnalysis)
            .expect("drift budget missing");
        let mut measurement = nominal_measurement(BpetComputation::DriftAnalysis);
        measurement.measured_p95_ms = budget.budget_p95_ms + 5.0;
        let outcome = evaluate_budget(&budget, &measurement);
        match outcome {
            BudgetOutcome::Degraded { code, .. } => assert_eq!(code, event_codes::BPET_PERF_005),
            _ => panic!("expected degraded outcome"),
        }
    }

    #[test]
    fn p99_or_storage_breach_fails_gate() {
        let budget = default_budgets()
            .into_iter()
            .find(|b| b.computation == BpetComputation::LineagePersistence)
            .expect("lineage budget missing");
        let mut measurement = nominal_measurement(BpetComputation::LineagePersistence);
        measurement.measured_storage_mb = budget.budget_storage_mb + 5.0;
        let outcome = evaluate_budget(&budget, &measurement);
        match outcome {
            BudgetOutcome::Fail { code, .. } => assert_eq!(code, event_codes::BPET_PERF_003),
            _ => panic!("expected failure outcome"),
        }
    }

    #[test]
    fn calibration_or_provenance_shortfall_fails_gate() {
        let budget = default_budgets()
            .into_iter()
            .find(|b| b.computation == BpetComputation::ClaimCompilation)
            .expect("claim compilation budget missing");
        let mut measurement = nominal_measurement(BpetComputation::ClaimCompilation);
        measurement.signed_provenance_present = 1;
        let outcome = evaluate_budget(&budget, &measurement);
        match outcome {
            BudgetOutcome::Fail { code, .. } => assert_eq!(code, event_codes::BPET_PERF_004),
            _ => panic!("expected failure outcome"),
        }
    }

    #[test]
    fn summary_blocks_when_any_violation_present() {
        let summary = summarize(&[
            BudgetOutcome::Pass,
            BudgetOutcome::Degraded {
                code: event_codes::BPET_PERF_005,
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
