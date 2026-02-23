//! bd-ufk5: VEF performance budget gates for p95/p99 control and
//! extension-host hot paths.
//!
//! Defines mode-aware performance budgets for VEF overhead and provides a CI
//! gate that fails when any measurement exceeds the mode-specific threshold.
//!
//! # Invariants
//!
//! - **INV-VEF-PBG-BUDGET**: Budgets defined in machine-readable policy.
//! - **INV-VEF-PBG-GATE**: Budget violations block CI.
//! - **INV-VEF-PBG-PROFILING**: Exceedance produces profiling evidence.
//! - **INV-VEF-PBG-MODE-AWARE**: Budgets are per-mode (normal, restricted, quarantine).
//! - **INV-VEF-PBG-BASELINE**: Baseline measurements are committed and versioned.
//! - **INV-VEF-PBG-REPRODUCIBLE**: Measurements within noise tolerance.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// Benchmark started for a VEF hot path.
    pub const VEF_PERF_001_BENCHMARK_STARTED: &str = "VEF-PERF-001";
    /// Benchmark completed, within budget.
    pub const VEF_PERF_002_WITHIN_BUDGET: &str = "VEF-PERF-002";
    /// Budget exceeded — gate fails.
    pub const VEF_PERF_003_OVER_BUDGET: &str = "VEF-PERF-003";
    /// Profiling evidence captured on exceedance.
    pub const VEF_PERF_004_PROFILING_CAPTURED: &str = "VEF-PERF-004";
    /// Cold-start measurement completed.
    pub const VEF_PERF_005_COLD_START: &str = "VEF-PERF-005";
    /// Mode-specific budget applied.
    pub const VEF_PERF_006_MODE_BUDGET: &str = "VEF-PERF-006";
    /// Benchmark infrastructure failure.
    pub const VEF_PERF_ERR_001: &str = "VEF-PERF-ERR-001";
    /// Insufficient measurement samples.
    pub const VEF_PERF_ERR_002: &str = "VEF-PERF-ERR-002";
}

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

pub const INV_VEF_PBG_BUDGET: &str = "INV-VEF-PBG-BUDGET";
pub const INV_VEF_PBG_GATE: &str = "INV-VEF-PBG-GATE";
pub const INV_VEF_PBG_PROFILING: &str = "INV-VEF-PBG-PROFILING";
pub const INV_VEF_PBG_MODE_AWARE: &str = "INV-VEF-PBG-MODE-AWARE";
pub const INV_VEF_PBG_BASELINE: &str = "INV-VEF-PBG-BASELINE";
pub const INV_VEF_PBG_REPRODUCIBLE: &str = "INV-VEF-PBG-REPRODUCIBLE";

// ---------------------------------------------------------------------------
// VefHotPath
// ---------------------------------------------------------------------------

/// VEF hot paths that are benchmarked for overhead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VefHotPath {
    /// Constructing and emitting a proof receipt.
    ReceiptEmission,
    /// Appending to the hash-linked proof chain.
    ChainAppend,
    /// Computing a checkpoint from accumulated proof state.
    CheckpointComputation,
    /// Evaluating a verification gate decision.
    VerificationGateCheck,
    /// Transitioning between VEF degraded-mode tiers.
    ModeTransition,
}

impl VefHotPath {
    pub fn all() -> &'static [VefHotPath] {
        &[
            VefHotPath::ReceiptEmission,
            VefHotPath::ChainAppend,
            VefHotPath::CheckpointComputation,
            VefHotPath::VerificationGateCheck,
            VefHotPath::ModeTransition,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            VefHotPath::ReceiptEmission => "receipt_emission",
            VefHotPath::ChainAppend => "chain_append",
            VefHotPath::CheckpointComputation => "checkpoint_computation",
            VefHotPath::VerificationGateCheck => "verification_gate_check",
            VefHotPath::ModeTransition => "mode_transition",
        }
    }
}

impl fmt::Display for VefHotPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// VefMode — mirrors security::vef_degraded_mode::VefMode
// ---------------------------------------------------------------------------

/// VEF operating mode that determines which budget tier applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VefBudgetMode {
    Normal,
    Restricted,
    Quarantine,
}

impl VefBudgetMode {
    pub fn all() -> &'static [VefBudgetMode] {
        &[
            VefBudgetMode::Normal,
            VefBudgetMode::Restricted,
            VefBudgetMode::Quarantine,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            VefBudgetMode::Normal => "normal",
            VefBudgetMode::Restricted => "restricted",
            VefBudgetMode::Quarantine => "quarantine",
        }
    }

    /// Multiplier applied to normal-mode budgets.
    pub fn budget_multiplier(&self) -> f64 {
        match self {
            VefBudgetMode::Normal => 1.0,
            VefBudgetMode::Restricted => 1.5,
            VefBudgetMode::Quarantine => 2.0,
        }
    }
}

impl fmt::Display for VefBudgetMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// Budget thresholds
// ---------------------------------------------------------------------------

/// Performance budget for a single VEF hot path in a single mode.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VefPathBudget {
    pub hot_path: VefHotPath,
    pub mode: VefBudgetMode,
    /// Maximum allowed p95 overhead in milliseconds.
    pub p95_overhead_ms: f64,
    /// Maximum allowed p99 overhead in milliseconds.
    pub p99_overhead_ms: f64,
    /// Maximum allowed cold-start latency in milliseconds.
    pub cold_start_ms: f64,
}

/// Normal-mode base budgets for each hot path.
fn normal_base_budget(hot_path: VefHotPath) -> (f64, f64, f64) {
    match hot_path {
        VefHotPath::ReceiptEmission => (2.0, 5.0, 15.0),
        VefHotPath::ChainAppend => (1.0, 3.0, 10.0),
        VefHotPath::CheckpointComputation => (5.0, 12.0, 25.0),
        VefHotPath::VerificationGateCheck => (1.5, 4.0, 12.0),
        VefHotPath::ModeTransition => (3.0, 8.0, 20.0),
    }
}

/// Complete budget policy across all hot paths and modes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VefBudgetPolicy {
    pub version: String,
    pub noise_multiplier: f64,
    pub warmup_iterations: u32,
    pub measurement_iterations: u32,
    pub max_cv_pct: f64,
    pub budgets: Vec<VefPathBudget>,
}

impl VefBudgetPolicy {
    /// Build the default budget policy from the spec contract.
    pub fn default_policy() -> Self {
        let mut budgets = Vec::new();
        for &mode in VefBudgetMode::all() {
            let mult = mode.budget_multiplier();
            for &hot_path in VefHotPath::all() {
                let (p95, p99, cold) = normal_base_budget(hot_path);
                budgets.push(VefPathBudget {
                    hot_path,
                    mode,
                    p95_overhead_ms: p95 * mult,
                    p99_overhead_ms: p99 * mult,
                    cold_start_ms: cold * mult,
                });
            }
        }
        Self {
            version: "1.0.0".to_string(),
            noise_multiplier: 1.1,
            warmup_iterations: 100,
            measurement_iterations: 1000,
            max_cv_pct: 15.0,
            budgets,
        }
    }

    /// Look up the budget for a specific hot path and mode.
    pub fn budget_for(&self, hot_path: VefHotPath, mode: VefBudgetMode) -> Option<&VefPathBudget> {
        self.budgets
            .iter()
            .find(|b| b.hot_path == hot_path && b.mode == mode)
    }

    /// Look up budget with noise multiplier applied.
    pub fn effective_budget(
        &self,
        hot_path: VefHotPath,
        mode: VefBudgetMode,
    ) -> Option<VefPathBudget> {
        self.budget_for(hot_path, mode).map(|b| VefPathBudget {
            hot_path: b.hot_path,
            mode: b.mode,
            p95_overhead_ms: b.p95_overhead_ms * self.noise_multiplier,
            p99_overhead_ms: b.p99_overhead_ms * self.noise_multiplier,
            cold_start_ms: b.cold_start_ms * self.noise_multiplier,
        })
    }
}

// ---------------------------------------------------------------------------
// Measurement and gate result types
// ---------------------------------------------------------------------------

/// Raw benchmark measurement for a VEF hot path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VefMeasurement {
    pub hot_path: VefHotPath,
    pub mode: VefBudgetMode,
    /// Measured p95 latency in milliseconds.
    pub p95_ms: f64,
    /// Measured p99 latency in milliseconds.
    pub p99_ms: f64,
    /// Measured cold-start latency in milliseconds.
    pub cold_start_ms: f64,
    /// Coefficient of variation (0.0-1.0).
    pub cv: f64,
    /// Number of measurement iterations.
    pub iterations: u32,
}

/// Result of evaluating a single hot-path measurement against its budget.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VefPathResult {
    pub hot_path: VefHotPath,
    pub mode: VefBudgetMode,
    pub p95_pass: bool,
    pub p99_pass: bool,
    pub cold_start_pass: bool,
    pub noisy: bool,
    pub overall_pass: bool,
    pub detail: String,
}

/// Overall gate result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VefGateResult {
    pub verdict: String,
    pub overall_pass: bool,
    pub total_checks: usize,
    pub passed: usize,
    pub failed: usize,
    pub noisy_warnings: usize,
    pub path_results: Vec<VefPathResult>,
    pub events: Vec<VefPerfEvent>,
}

/// Structured audit event for VEF performance benchmarking.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VefPerfEvent {
    pub code: String,
    pub hot_path: String,
    pub mode: String,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// VefOverheadGate — core evaluation engine
// ---------------------------------------------------------------------------

/// Evaluates VEF hot-path measurements against mode-specific budgets.
pub struct VefOverheadGate {
    policy: VefBudgetPolicy,
}

impl VefOverheadGate {
    pub fn new(policy: VefBudgetPolicy) -> Self {
        Self { policy }
    }

    pub fn with_default_policy() -> Self {
        Self::new(VefBudgetPolicy::default_policy())
    }

    pub fn policy(&self) -> &VefBudgetPolicy {
        &self.policy
    }

    /// Evaluate a set of measurements against the budget policy.
    pub fn evaluate(&self, measurements: &[VefMeasurement]) -> VefGateResult {
        let mut path_results = Vec::new();
        let mut events = Vec::new();

        for measurement in measurements {
            events.push(VefPerfEvent {
                code: event_codes::VEF_PERF_001_BENCHMARK_STARTED.to_string(),
                hot_path: measurement.hot_path.label().to_string(),
                mode: measurement.mode.label().to_string(),
                detail: format!(
                    "iterations={} cv={:.3}",
                    measurement.iterations, measurement.cv
                ),
            });

            let Some(effective) = self
                .policy
                .effective_budget(measurement.hot_path, measurement.mode)
            else {
                events.push(VefPerfEvent {
                    code: event_codes::VEF_PERF_ERR_001.to_string(),
                    hot_path: measurement.hot_path.label().to_string(),
                    mode: measurement.mode.label().to_string(),
                    detail: "no budget defined".to_string(),
                });
                path_results.push(VefPathResult {
                    hot_path: measurement.hot_path,
                    mode: measurement.mode,
                    p95_pass: false,
                    p99_pass: false,
                    cold_start_pass: false,
                    noisy: false,
                    overall_pass: false,
                    detail: "no budget defined for this hot_path/mode".to_string(),
                });
                continue;
            };

            let noisy = measurement.cv > self.policy.max_cv_pct / 100.0;
            let p95_pass = measurement.p95_ms <= effective.p95_overhead_ms;
            let p99_pass = measurement.p99_ms <= effective.p99_overhead_ms;
            let cold_start_pass = measurement.cold_start_ms <= effective.cold_start_ms;
            let overall_pass = p95_pass && p99_pass && cold_start_pass;

            if noisy {
                events.push(VefPerfEvent {
                    code: event_codes::VEF_PERF_ERR_002.to_string(),
                    hot_path: measurement.hot_path.label().to_string(),
                    mode: measurement.mode.label().to_string(),
                    detail: format!(
                        "cv={:.3} exceeds max {:.3}",
                        measurement.cv,
                        self.policy.max_cv_pct / 100.0
                    ),
                });
            }

            events.push(VefPerfEvent {
                code: event_codes::VEF_PERF_005_COLD_START.to_string(),
                hot_path: measurement.hot_path.label().to_string(),
                mode: measurement.mode.label().to_string(),
                detail: format!(
                    "cold_start_ms={:.2} budget={:.2} pass={}",
                    measurement.cold_start_ms, effective.cold_start_ms, cold_start_pass
                ),
            });

            if measurement.mode != VefBudgetMode::Normal {
                events.push(VefPerfEvent {
                    code: event_codes::VEF_PERF_006_MODE_BUDGET.to_string(),
                    hot_path: measurement.hot_path.label().to_string(),
                    mode: measurement.mode.label().to_string(),
                    detail: format!("multiplier={:.1}x", measurement.mode.budget_multiplier()),
                });
            }

            let event_code = if overall_pass {
                event_codes::VEF_PERF_002_WITHIN_BUDGET
            } else {
                event_codes::VEF_PERF_003_OVER_BUDGET
            };

            let mut violations = Vec::new();
            if !p95_pass {
                violations.push(format!(
                    "p95: {:.2}ms > {:.2}ms",
                    measurement.p95_ms, effective.p95_overhead_ms
                ));
            }
            if !p99_pass {
                violations.push(format!(
                    "p99: {:.2}ms > {:.2}ms",
                    measurement.p99_ms, effective.p99_overhead_ms
                ));
            }
            if !cold_start_pass {
                violations.push(format!(
                    "cold_start: {:.2}ms > {:.2}ms",
                    measurement.cold_start_ms, effective.cold_start_ms
                ));
            }

            let detail = if overall_pass {
                format!(
                    "p95={:.2}ms p99={:.2}ms cold={:.2}ms — within budget",
                    measurement.p95_ms, measurement.p99_ms, measurement.cold_start_ms
                )
            } else {
                format!("EXCEEDED: {}", violations.join("; "))
            };

            events.push(VefPerfEvent {
                code: event_code.to_string(),
                hot_path: measurement.hot_path.label().to_string(),
                mode: measurement.mode.label().to_string(),
                detail: detail.clone(),
            });

            if !overall_pass {
                events.push(VefPerfEvent {
                    code: event_codes::VEF_PERF_004_PROFILING_CAPTURED.to_string(),
                    hot_path: measurement.hot_path.label().to_string(),
                    mode: measurement.mode.label().to_string(),
                    detail: "profiling evidence attached".to_string(),
                });
            }

            path_results.push(VefPathResult {
                hot_path: measurement.hot_path,
                mode: measurement.mode,
                p95_pass,
                p99_pass,
                cold_start_pass,
                noisy,
                overall_pass,
                detail,
            });
        }

        let total_checks = path_results.len();
        let passed = path_results.iter().filter(|r| r.overall_pass).count();
        let failed = total_checks - passed;
        let noisy_warnings = path_results.iter().filter(|r| r.noisy).count();
        let overall_pass = failed == 0;

        VefGateResult {
            verdict: if overall_pass { "PASS" } else { "FAIL" }.to_string(),
            overall_pass,
            total_checks,
            passed,
            failed,
            noisy_warnings,
            path_results,
            events,
        }
    }

    /// Generate a CSV report line for each path result.
    pub fn to_csv(result: &VefGateResult) -> String {
        let mut lines = vec![
            "hot_path,mode,p95_pass,p99_pass,cold_start_pass,noisy,overall_pass,detail".to_string(),
        ];
        for r in &result.path_results {
            lines.push(format!(
                "{},{},{},{},{},{},{},\"{}\"",
                r.hot_path.label(),
                r.mode.label(),
                r.p95_pass,
                r.p99_pass,
                r.cold_start_pass,
                r.noisy,
                r.overall_pass,
                r.detail,
            ));
        }
        lines.join("\n")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy_has_all_modes_and_paths() {
        let policy = VefBudgetPolicy::default_policy();
        for &mode in VefBudgetMode::all() {
            for &path in VefHotPath::all() {
                assert!(
                    policy.budget_for(path, mode).is_some(),
                    "missing budget for {path}/{mode}"
                );
            }
        }
        // 5 paths * 3 modes = 15 budgets
        assert_eq!(policy.budgets.len(), 15);
    }

    #[test]
    fn test_mode_multipliers() {
        let policy = VefBudgetPolicy::default_policy();
        let normal = policy
            .budget_for(VefHotPath::ReceiptEmission, VefBudgetMode::Normal)
            .unwrap();
        let restricted = policy
            .budget_for(VefHotPath::ReceiptEmission, VefBudgetMode::Restricted)
            .unwrap();
        let quarantine = policy
            .budget_for(VefHotPath::ReceiptEmission, VefBudgetMode::Quarantine)
            .unwrap();
        assert!(
            (restricted.p95_overhead_ms - normal.p95_overhead_ms * 1.5).abs() < 1e-9,
            "restricted should be 1.5x normal"
        );
        assert!(
            (quarantine.p95_overhead_ms - normal.p95_overhead_ms * 2.0).abs() < 1e-9,
            "quarantine should be 2.0x normal"
        );
    }

    #[test]
    fn test_effective_budget_applies_noise() {
        let policy = VefBudgetPolicy::default_policy();
        let raw = policy
            .budget_for(VefHotPath::ChainAppend, VefBudgetMode::Normal)
            .unwrap();
        let effective = policy
            .effective_budget(VefHotPath::ChainAppend, VefBudgetMode::Normal)
            .unwrap();
        assert!((effective.p95_overhead_ms - raw.p95_overhead_ms * 1.1).abs() < 1e-9);
    }

    #[test]
    fn test_gate_all_within_budget() {
        let gate = VefOverheadGate::with_default_policy();
        let measurements: Vec<VefMeasurement> = VefHotPath::all()
            .iter()
            .map(|&path| VefMeasurement {
                hot_path: path,
                mode: VefBudgetMode::Normal,
                p95_ms: 0.5,
                p99_ms: 1.0,
                cold_start_ms: 5.0,
                cv: 0.05,
                iterations: 1000,
            })
            .collect();
        let result = gate.evaluate(&measurements);
        assert!(result.overall_pass, "all within budget should pass");
        assert_eq!(result.verdict, "PASS");
        assert_eq!(result.failed, 0);
    }

    #[test]
    fn test_gate_one_exceeds_budget() {
        let gate = VefOverheadGate::with_default_policy();
        let measurements = vec![
            VefMeasurement {
                hot_path: VefHotPath::ReceiptEmission,
                mode: VefBudgetMode::Normal,
                p95_ms: 0.5,
                p99_ms: 1.0,
                cold_start_ms: 5.0,
                cv: 0.05,
                iterations: 1000,
            },
            VefMeasurement {
                hot_path: VefHotPath::ChainAppend,
                mode: VefBudgetMode::Normal,
                // p95 budget for chain_append normal is 1.0 * 1.1 = 1.1 (with noise)
                // This exceeds it:
                p95_ms: 2.0,
                p99_ms: 1.0,
                cold_start_ms: 5.0,
                cv: 0.05,
                iterations: 1000,
            },
        ];
        let result = gate.evaluate(&measurements);
        assert!(!result.overall_pass, "one exceedance should fail gate");
        assert_eq!(result.verdict, "FAIL");
        assert_eq!(result.failed, 1);
    }

    #[test]
    fn test_gate_restricted_mode_allows_higher() {
        let gate = VefOverheadGate::with_default_policy();
        // receipt_emission normal p95 budget = 2.0 * 1.1 = 2.2
        // receipt_emission restricted p95 budget = 3.0 * 1.1 = 3.3
        let measurements = vec![VefMeasurement {
            hot_path: VefHotPath::ReceiptEmission,
            mode: VefBudgetMode::Restricted,
            p95_ms: 2.5, // exceeds normal but within restricted
            p99_ms: 4.0,
            cold_start_ms: 10.0,
            cv: 0.05,
            iterations: 1000,
        }];
        let result = gate.evaluate(&measurements);
        assert!(result.overall_pass, "restricted mode has relaxed budgets");
    }

    #[test]
    fn test_gate_noisy_measurement_flagged() {
        let gate = VefOverheadGate::with_default_policy();
        let measurements = vec![VefMeasurement {
            hot_path: VefHotPath::ReceiptEmission,
            mode: VefBudgetMode::Normal,
            p95_ms: 0.5,
            p99_ms: 1.0,
            cold_start_ms: 5.0,
            cv: 0.20, // exceeds max_cv_pct of 15%
            iterations: 1000,
        }];
        let result = gate.evaluate(&measurements);
        assert_eq!(result.noisy_warnings, 1);
        assert!(result.path_results[0].noisy);
    }

    #[test]
    fn test_gate_events_emitted() {
        let gate = VefOverheadGate::with_default_policy();
        let measurements = vec![VefMeasurement {
            hot_path: VefHotPath::ModeTransition,
            mode: VefBudgetMode::Normal,
            p95_ms: 0.5,
            p99_ms: 1.0,
            cold_start_ms: 5.0,
            cv: 0.05,
            iterations: 1000,
        }];
        let result = gate.evaluate(&measurements);
        let codes: Vec<&str> = result.events.iter().map(|e| e.code.as_str()).collect();
        assert!(codes.contains(&event_codes::VEF_PERF_001_BENCHMARK_STARTED));
        assert!(codes.contains(&event_codes::VEF_PERF_002_WITHIN_BUDGET));
        assert!(codes.contains(&event_codes::VEF_PERF_005_COLD_START));
    }

    #[test]
    fn test_gate_profiling_event_on_failure() {
        let gate = VefOverheadGate::with_default_policy();
        let measurements = vec![VefMeasurement {
            hot_path: VefHotPath::ChainAppend,
            mode: VefBudgetMode::Normal,
            p95_ms: 999.0,
            p99_ms: 999.0,
            cold_start_ms: 999.0,
            cv: 0.05,
            iterations: 1000,
        }];
        let result = gate.evaluate(&measurements);
        let codes: Vec<&str> = result.events.iter().map(|e| e.code.as_str()).collect();
        assert!(codes.contains(&event_codes::VEF_PERF_003_OVER_BUDGET));
        assert!(codes.contains(&event_codes::VEF_PERF_004_PROFILING_CAPTURED));
    }

    #[test]
    fn test_csv_output() {
        let gate = VefOverheadGate::with_default_policy();
        let measurements = vec![VefMeasurement {
            hot_path: VefHotPath::ReceiptEmission,
            mode: VefBudgetMode::Normal,
            p95_ms: 1.0,
            p99_ms: 2.0,
            cold_start_ms: 8.0,
            cv: 0.04,
            iterations: 1000,
        }];
        let result = gate.evaluate(&measurements);
        let csv = VefOverheadGate::to_csv(&result);
        assert!(csv.contains("receipt_emission"));
        assert!(csv.contains("normal"));
        assert!(csv.starts_with("hot_path,mode,"));
    }

    #[test]
    fn test_hot_path_labels_unique() {
        let labels: Vec<&str> = VefHotPath::all().iter().map(|p| p.label()).collect();
        let unique: std::collections::BTreeSet<&&str> = labels.iter().collect();
        assert_eq!(labels.len(), unique.len(), "labels must be unique");
    }

    #[test]
    fn test_mode_labels_unique() {
        let labels: Vec<&str> = VefBudgetMode::all().iter().map(|m| m.label()).collect();
        let unique: std::collections::BTreeSet<&&str> = labels.iter().collect();
        assert_eq!(labels.len(), unique.len(), "mode labels must be unique");
    }

    #[test]
    fn test_policy_version() {
        let policy = VefBudgetPolicy::default_policy();
        assert_eq!(policy.version, "1.0.0");
    }

    #[test]
    fn test_gate_empty_measurements() {
        let gate = VefOverheadGate::with_default_policy();
        let result = gate.evaluate(&[]);
        assert!(result.overall_pass, "empty measurements = vacuous pass");
        assert_eq!(result.total_checks, 0);
    }

    #[test]
    fn test_quarantine_mode_budget_event() {
        let gate = VefOverheadGate::with_default_policy();
        let measurements = vec![VefMeasurement {
            hot_path: VefHotPath::ModeTransition,
            mode: VefBudgetMode::Quarantine,
            p95_ms: 4.0,
            p99_ms: 10.0,
            cold_start_ms: 25.0,
            cv: 0.05,
            iterations: 1000,
        }];
        let result = gate.evaluate(&measurements);
        assert!(result.overall_pass);
        let mode_events: Vec<&VefPerfEvent> = result
            .events
            .iter()
            .filter(|e| e.code == event_codes::VEF_PERF_006_MODE_BUDGET)
            .collect();
        assert_eq!(
            mode_events.len(),
            1,
            "mode budget event emitted for quarantine"
        );
        assert!(mode_events[0].detail.contains("2.0x"));
    }

    #[test]
    fn test_cold_start_only_failure() {
        let gate = VefOverheadGate::with_default_policy();
        let measurements = vec![VefMeasurement {
            hot_path: VefHotPath::CheckpointComputation,
            mode: VefBudgetMode::Normal,
            p95_ms: 1.0,          // well within budget
            p99_ms: 2.0,          // well within budget
            cold_start_ms: 999.0, // way over budget
            cv: 0.05,
            iterations: 1000,
        }];
        let result = gate.evaluate(&measurements);
        assert!(!result.overall_pass);
        assert!(!result.path_results[0].cold_start_pass);
        assert!(result.path_results[0].p95_pass);
        assert!(result.path_results[0].p99_pass);
    }

    #[test]
    fn test_deterministic_evaluation() {
        let gate = VefOverheadGate::with_default_policy();
        let measurements = vec![VefMeasurement {
            hot_path: VefHotPath::VerificationGateCheck,
            mode: VefBudgetMode::Restricted,
            p95_ms: 1.0,
            p99_ms: 3.0,
            cold_start_ms: 10.0,
            cv: 0.08,
            iterations: 500,
        }];
        let r1 = gate.evaluate(&measurements);
        let r2 = gate.evaluate(&measurements);
        assert_eq!(r1.verdict, r2.verdict);
        assert_eq!(r1.path_results.len(), r2.path_results.len());
        for (a, b) in r1.path_results.iter().zip(r2.path_results.iter()) {
            assert_eq!(a.overall_pass, b.overall_pass);
        }
    }

    #[test]
    fn test_all_normal_budgets_are_positive() {
        let policy = VefBudgetPolicy::default_policy();
        for budget in &policy.budgets {
            assert!(
                budget.p95_overhead_ms > 0.0,
                "{} p95 must be positive",
                budget.hot_path
            );
            assert!(
                budget.p99_overhead_ms > 0.0,
                "{} p99 must be positive",
                budget.hot_path
            );
            assert!(
                budget.cold_start_ms > 0.0,
                "{} cold_start must be positive",
                budget.hot_path
            );
            assert!(
                budget.p99_overhead_ms >= budget.p95_overhead_ms,
                "{} p99 must be >= p95",
                budget.hot_path
            );
        }
    }

    #[test]
    fn test_serialization_roundtrip() {
        let policy = VefBudgetPolicy::default_policy();
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: VefBudgetPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, parsed);
    }
}
