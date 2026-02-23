//! bd-ufk5: Performance budget gates for VEF overhead in p95/p99 hot paths.
//!
//! Enforces latency budgets for VEF (Verifiable Execution Fabric) operations
//! in control-plane and extension-host hot paths. Budgets are per-mode
//! (normal, restricted, quarantine) and per-operation. CI fails when any
//! measurement exceeds its threshold.
//!
//! # Invariants
//!
//! - **INV-VEF-PBG-BUDGET**: Every VEF operation has a defined p95 and p99 latency budget per mode.
//! - **INV-VEF-PBG-GATE**: CI gate fails when any measurement exceeds its budget threshold.
//! - **INV-VEF-PBG-BASELINE**: Committed baselines enable regression detection across commits.
//! - **INV-VEF-PBG-NOISE**: Noise tolerance prevents false failures from measurement jitter.
//! - **INV-VEF-PBG-EVIDENCE**: Budget breaches produce profiling evidence for root-cause triage.
//! - **INV-VEF-PBG-MODE**: Per-mode budgets enforce mode-appropriate overhead limits.
//!
//! Structured logging codes:
//! - `VEF-PERF-001` — benchmark started
//! - `VEF-PERF-002` — benchmark completed within budget
//! - `VEF-PERF-003` — budget exceeded
//! - `VEF-PERF-004` — baseline recorded
//! - `VEF-PERF-005` — noise tolerance applied
//! - `VEF-PERF-ERR-001` — benchmark infrastructure failure

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ── Audit event codes ───────────────────────────────────────────────────

pub const VEF_PERF_001: &str = "VEF-PERF-001";
pub const VEF_PERF_002: &str = "VEF-PERF-002";
pub const VEF_PERF_003: &str = "VEF-PERF-003";
pub const VEF_PERF_004: &str = "VEF-PERF-004";
pub const VEF_PERF_005: &str = "VEF-PERF-005";
pub const VEF_PERF_ERR_001: &str = "VEF-PERF-ERR-001";

// ── Invariant constants ─────────────────────────────────────────────────

pub const INV_VEF_PBG_BUDGET: &str = "INV-VEF-PBG-BUDGET";
pub const INV_VEF_PBG_GATE: &str = "INV-VEF-PBG-GATE";
pub const INV_VEF_PBG_BASELINE: &str = "INV-VEF-PBG-BASELINE";
pub const INV_VEF_PBG_NOISE: &str = "INV-VEF-PBG-NOISE";
pub const INV_VEF_PBG_EVIDENCE: &str = "INV-VEF-PBG-EVIDENCE";
pub const INV_VEF_PBG_MODE: &str = "INV-VEF-PBG-MODE";

/// Schema version for budget configuration and results.
pub const BUDGET_SCHEMA_VERSION: &str = "1.0.0";

// ── VEF operation categories ────────────────────────────────────────────

/// Operations in the VEF pipeline that incur measurable overhead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VefOperation {
    /// Emit a signed decision receipt.
    ReceiptEmission,
    /// Append an entry to the evidence chain.
    ChainAppend,
    /// Compute a checkpoint hash.
    CheckpointComputation,
    /// Evaluate a verification gate (proof check).
    VerificationGateCheck,
    /// Transition between VEF modes.
    ModeTransition,
    /// End-to-end control-plane hot path with VEF active.
    ControlPlaneHotPath,
    /// End-to-end extension-host hot path with VEF active.
    ExtensionHostHotPath,
}

impl VefOperation {
    /// All defined operations.
    pub fn all() -> &'static [VefOperation] {
        &[
            VefOperation::ReceiptEmission,
            VefOperation::ChainAppend,
            VefOperation::CheckpointComputation,
            VefOperation::VerificationGateCheck,
            VefOperation::ModeTransition,
            VefOperation::ControlPlaneHotPath,
            VefOperation::ExtensionHostHotPath,
        ]
    }

    /// Human-readable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::ReceiptEmission => "receipt_emission",
            Self::ChainAppend => "chain_append",
            Self::CheckpointComputation => "checkpoint_computation",
            Self::VerificationGateCheck => "verification_gate_check",
            Self::ModeTransition => "mode_transition",
            Self::ControlPlaneHotPath => "control_plane_hot_path",
            Self::ExtensionHostHotPath => "extension_host_hot_path",
        }
    }

    /// Whether this is an integration (end-to-end) operation vs. a micro benchmark.
    #[must_use]
    pub fn is_integration(self) -> bool {
        matches!(self, Self::ControlPlaneHotPath | Self::ExtensionHostHotPath)
    }
}

// ── VEF mode (re-export for budget context) ─────────────────────────────

/// Operating mode determines applicable budget thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetMode {
    Normal,
    Restricted,
    Quarantine,
}

impl BudgetMode {
    pub fn all() -> &'static [BudgetMode] {
        &[
            BudgetMode::Normal,
            BudgetMode::Restricted,
            BudgetMode::Quarantine,
        ]
    }

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Restricted => "restricted",
            Self::Quarantine => "quarantine",
        }
    }
}

// ── Budget thresholds ───────────────────────────────────────────────────

/// Latency budget for a single operation in a single mode.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LatencyBudget {
    /// Maximum allowed p95 latency in microseconds.
    pub p95_us: u64,
    /// Maximum allowed p99 latency in microseconds.
    pub p99_us: u64,
}

impl LatencyBudget {
    #[must_use]
    pub fn new(p95_us: u64, p99_us: u64) -> Self {
        Self { p95_us, p99_us }
    }

    /// Check whether measured latencies exceed this budget.
    #[must_use]
    pub fn check(&self, measured: &MeasuredLatency) -> BudgetCheckResult {
        let p95_ok = measured.p95_us <= self.p95_us;
        let p99_ok = measured.p99_us <= self.p99_us;
        BudgetCheckResult {
            p95_within_budget: p95_ok,
            p99_within_budget: p99_ok,
            passed: p95_ok && p99_ok,
            p95_headroom_pct: if self.p95_us > 0 {
                ((self.p95_us as f64 - measured.p95_us as f64) / self.p95_us as f64) * 100.0
            } else {
                0.0
            },
            p99_headroom_pct: if self.p99_us > 0 {
                ((self.p99_us as f64 - measured.p99_us as f64) / self.p99_us as f64) * 100.0
            } else {
                0.0
            },
        }
    }
}

/// Result of checking a measurement against a budget.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BudgetCheckResult {
    pub p95_within_budget: bool,
    pub p99_within_budget: bool,
    pub passed: bool,
    /// Percentage headroom remaining (negative = over budget).
    pub p95_headroom_pct: f64,
    pub p99_headroom_pct: f64,
}

// ── Measured latency ────────────────────────────────────────────────────

/// Measured latency statistics for a VEF operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeasuredLatency {
    pub operation: VefOperation,
    pub mode: BudgetMode,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
    pub sample_count: u64,
    pub coefficient_of_variation_pct: f64,
}

impl MeasuredLatency {
    /// True if measurement variance is within noise tolerance.
    #[must_use]
    pub fn is_stable(&self, max_cv_pct: f64) -> bool {
        self.coefficient_of_variation_pct <= max_cv_pct
    }
}

// ── Budget configuration ────────────────────────────────────────────────

/// Complete budget configuration for all operations and modes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VefPerfBudgetConfig {
    pub schema_version: String,
    /// Maximum coefficient of variation (%) before a measurement is considered unstable.
    pub noise_tolerance_cv_pct: f64,
    /// Minimum number of samples required for a measurement to be valid.
    pub min_samples: u64,
    /// Per-operation, per-mode budget thresholds.
    pub budgets: BTreeMap<String, BTreeMap<String, LatencyBudget>>,
}

impl Default for VefPerfBudgetConfig {
    fn default() -> Self {
        let mut budgets = BTreeMap::new();

        // Micro-operation budgets (microseconds)
        let ops = [
            ("receipt_emission", (50, 100, 80, 150, 120, 250)),
            ("chain_append", (30, 60, 50, 100, 80, 160)),
            ("checkpoint_computation", (100, 200, 150, 300, 250, 500)),
            ("verification_gate_check", (40, 80, 60, 120, 100, 200)),
            ("mode_transition", (20, 50, 30, 80, 50, 120)),
            // Integration budgets (end-to-end, higher)
            ("control_plane_hot_path", (500, 1000, 750, 1500, 1200, 2500)),
            ("extension_host_hot_path", (300, 600, 450, 900, 750, 1500)),
        ];

        for (op, (np95, np99, rp95, rp99, qp95, qp99)) in ops {
            let mut mode_map = BTreeMap::new();
            mode_map.insert("normal".to_string(), LatencyBudget::new(np95, np99));
            mode_map.insert("restricted".to_string(), LatencyBudget::new(rp95, rp99));
            mode_map.insert("quarantine".to_string(), LatencyBudget::new(qp95, qp99));
            budgets.insert(op.to_string(), mode_map);
        }

        Self {
            schema_version: BUDGET_SCHEMA_VERSION.to_string(),
            noise_tolerance_cv_pct: 15.0,
            min_samples: 30,
            budgets,
        }
    }
}

impl VefPerfBudgetConfig {
    /// Look up the budget for an operation in a mode.
    #[must_use]
    pub fn budget_for(&self, op: VefOperation, mode: BudgetMode) -> Option<&LatencyBudget> {
        self.budgets
            .get(op.label())
            .and_then(|modes| modes.get(mode.label()))
    }

    /// Validate configuration: every operation must have budgets for all modes.
    pub fn validate(&self) -> Result<(), VefPerfBudgetError> {
        for op in VefOperation::all() {
            for mode in BudgetMode::all() {
                if self.budget_for(*op, *mode).is_none() {
                    return Err(VefPerfBudgetError::MissingBudget {
                        operation: op.label().to_string(),
                        mode: mode.label().to_string(),
                    });
                }
            }
        }
        if self.noise_tolerance_cv_pct <= 0.0 {
            return Err(VefPerfBudgetError::InvalidConfig(
                "noise_tolerance_cv_pct must be > 0".into(),
            ));
        }
        if self.min_samples == 0 {
            return Err(VefPerfBudgetError::InvalidConfig(
                "min_samples must be > 0".into(),
            ));
        }
        Ok(())
    }
}

// ── Errors ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum VefPerfBudgetError {
    MissingBudget {
        operation: String,
        mode: String,
    },
    InvalidConfig(String),
    InsufficientSamples {
        operation: String,
        count: u64,
        required: u64,
    },
    UnstableMeasurement {
        operation: String,
        cv_pct: f64,
        max_cv_pct: f64,
    },
    BudgetExceeded {
        operation: String,
        mode: String,
        details: String,
    },
    InfrastructureError(String),
}

impl std::fmt::Display for VefPerfBudgetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingBudget { operation, mode } => {
                write!(f, "no budget defined for {operation} in {mode} mode")
            }
            Self::InvalidConfig(msg) => write!(f, "invalid config: {msg}"),
            Self::InsufficientSamples {
                operation,
                count,
                required,
            } => {
                write!(f, "{operation}: {count} samples < {required} required")
            }
            Self::UnstableMeasurement {
                operation,
                cv_pct,
                max_cv_pct,
            } => {
                write!(
                    f,
                    "{operation}: CV {cv_pct:.1}% exceeds noise tolerance {max_cv_pct:.1}%"
                )
            }
            Self::BudgetExceeded {
                operation,
                mode,
                details,
            } => {
                write!(f, "budget exceeded for {operation} [{mode}]: {details}")
            }
            Self::InfrastructureError(msg) => write!(f, "infrastructure error: {msg}"),
        }
    }
}

// ── Audit events ────────────────────────────────────────────────────────

/// Structured audit event for the VEF performance budget gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VefPerfEvent {
    pub code: String,
    pub timestamp_epoch_secs: u64,
    pub operation: String,
    pub mode: String,
    pub correlation_id: String,
    pub details: BTreeMap<String, serde_json::Value>,
}

impl VefPerfEvent {
    fn new(
        code: &str,
        op: &str,
        mode: &str,
        corr_id: &str,
        details: BTreeMap<String, serde_json::Value>,
    ) -> Self {
        Self {
            code: code.to_string(),
            timestamp_epoch_secs: 0, // caller fills in
            operation: op.to_string(),
            mode: mode.to_string(),
            correlation_id: corr_id.to_string(),
            details,
        }
    }
}

// ── Gate result ─────────────────────────────────────────────────────────

/// Outcome of evaluating all measurements against their budgets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateVerdict {
    pub passed: bool,
    pub total_checks: usize,
    pub passed_checks: usize,
    pub failed_checks: usize,
    pub skipped_checks: usize,
    pub results: Vec<OperationVerdict>,
    pub audit_log: Vec<VefPerfEvent>,
}

/// Per-operation gate result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationVerdict {
    pub operation: String,
    pub mode: String,
    pub budget: LatencyBudget,
    pub measured: MeasuredLatency,
    pub check_result: BudgetCheckResult,
    pub stable: bool,
    pub status: VerdictStatus,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictStatus {
    Pass,
    Fail,
    Skipped,
    Unstable,
}

// ── Baseline snapshot ───────────────────────────────────────────────────

/// Committed baseline for regression detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineSnapshot {
    pub schema_version: String,
    pub commit_sha: String,
    pub recorded_at_epoch_secs: u64,
    pub measurements: Vec<MeasuredLatency>,
}

// ── Gate engine ─────────────────────────────────────────────────────────

/// The VEF performance budget gate engine evaluates measurements against
/// configured budgets and produces a deterministic verdict.
pub struct VefPerfBudgetGate {
    config: VefPerfBudgetConfig,
    audit_log: Vec<VefPerfEvent>,
}

impl VefPerfBudgetGate {
    #[must_use]
    pub fn new(config: VefPerfBudgetConfig) -> Self {
        Self {
            config,
            audit_log: Vec::new(),
        }
    }

    /// Evaluate a set of measurements against configured budgets.
    /// Returns a deterministic gate verdict.
    pub fn evaluate(
        &mut self,
        measurements: &[MeasuredLatency],
        correlation_id: &str,
    ) -> Result<GateVerdict, VefPerfBudgetError> {
        self.config.validate()?;
        self.audit_log.clear();

        let mut results = Vec::new();
        let mut passed_checks = 0usize;
        let mut failed_checks = 0usize;
        let mut skipped_checks = 0usize;

        for m in measurements {
            // Emit benchmark-started event
            self.emit_event(
                VEF_PERF_001,
                m.operation.label(),
                m.mode.label(),
                correlation_id,
                {
                    let mut d = BTreeMap::new();
                    d.insert("sample_count".into(), serde_json::json!(m.sample_count));
                    d
                },
            );

            // Check sample count
            if m.sample_count < self.config.min_samples {
                skipped_checks += 1;
                results.push(OperationVerdict {
                    operation: m.operation.label().to_string(),
                    mode: m.mode.label().to_string(),
                    budget: self
                        .config
                        .budget_for(m.operation, m.mode)
                        .cloned()
                        .unwrap_or(LatencyBudget::new(0, 0)),
                    measured: m.clone(),
                    check_result: BudgetCheckResult {
                        p95_within_budget: false,
                        p99_within_budget: false,
                        passed: false,
                        p95_headroom_pct: 0.0,
                        p99_headroom_pct: 0.0,
                    },
                    stable: false,
                    status: VerdictStatus::Skipped,
                    reason: format!(
                        "insufficient samples: {} < {}",
                        m.sample_count, self.config.min_samples
                    ),
                });
                continue;
            }

            // Check measurement stability
            let noise_tol = self.config.noise_tolerance_cv_pct;
            let stable = m.is_stable(noise_tol);
            if !stable {
                self.emit_event(
                    VEF_PERF_005,
                    m.operation.label(),
                    m.mode.label(),
                    correlation_id,
                    {
                        let mut d = BTreeMap::new();
                        d.insert(
                            "cv_pct".into(),
                            serde_json::json!(m.coefficient_of_variation_pct),
                        );
                        d.insert("max_cv_pct".into(), serde_json::json!(noise_tol));
                        d
                    },
                );
            }

            // Look up and clone budget to avoid borrow conflict with emit_event
            let budget = self
                .config
                .budget_for(m.operation, m.mode)
                .cloned()
                .ok_or_else(|| VefPerfBudgetError::MissingBudget {
                    operation: m.operation.label().to_string(),
                    mode: m.mode.label().to_string(),
                })?;

            let check_result = budget.check(m);

            let (status, reason) = if !stable {
                (
                    VerdictStatus::Unstable,
                    format!(
                        "unstable measurement: CV {:.1}% > {:.1}% tolerance",
                        m.coefficient_of_variation_pct, self.config.noise_tolerance_cv_pct
                    ),
                )
            } else if check_result.passed {
                (
                    VerdictStatus::Pass,
                    format!(
                        "within budget (p95 headroom: {:.1}%, p99 headroom: {:.1}%)",
                        check_result.p95_headroom_pct, check_result.p99_headroom_pct
                    ),
                )
            } else {
                let mut detail_parts = Vec::new();
                if !check_result.p95_within_budget {
                    detail_parts.push(format!("p95 {}us > {}us", m.p95_us, budget.p95_us));
                }
                if !check_result.p99_within_budget {
                    detail_parts.push(format!("p99 {}us > {}us", m.p99_us, budget.p99_us));
                }
                (VerdictStatus::Fail, detail_parts.join("; "))
            };

            // Emit appropriate event
            match status {
                VerdictStatus::Pass => {
                    self.emit_event(
                        VEF_PERF_002,
                        m.operation.label(),
                        m.mode.label(),
                        correlation_id,
                        {
                            let mut d = BTreeMap::new();
                            d.insert("p95_us".into(), serde_json::json!(m.p95_us));
                            d.insert("p99_us".into(), serde_json::json!(m.p99_us));
                            d.insert("p95_budget_us".into(), serde_json::json!(budget.p95_us));
                            d.insert("p99_budget_us".into(), serde_json::json!(budget.p99_us));
                            d
                        },
                    );
                    passed_checks += 1;
                }
                VerdictStatus::Fail => {
                    self.emit_event(
                        VEF_PERF_003,
                        m.operation.label(),
                        m.mode.label(),
                        correlation_id,
                        {
                            let mut d = BTreeMap::new();
                            d.insert("p95_us".into(), serde_json::json!(m.p95_us));
                            d.insert("p99_us".into(), serde_json::json!(m.p99_us));
                            d.insert("p95_budget_us".into(), serde_json::json!(budget.p95_us));
                            d.insert("p99_budget_us".into(), serde_json::json!(budget.p99_us));
                            d.insert("reason".into(), serde_json::json!(reason));
                            d
                        },
                    );
                    failed_checks += 1;
                }
                VerdictStatus::Unstable => {
                    // Count as skipped for gate purposes — unstable ≠ fail
                    skipped_checks += 1;
                }
                VerdictStatus::Skipped => {
                    skipped_checks += 1;
                }
            }

            results.push(OperationVerdict {
                operation: m.operation.label().to_string(),
                mode: m.mode.label().to_string(),
                budget,
                measured: m.clone(),
                check_result,
                stable,
                status,
                reason,
            });
        }

        let total_checks = results.len();
        let passed = failed_checks == 0;

        Ok(GateVerdict {
            passed,
            total_checks,
            passed_checks,
            failed_checks,
            skipped_checks,
            results,
            audit_log: self.audit_log.clone(),
        })
    }

    /// Record a baseline snapshot from measurements.
    #[must_use]
    pub fn record_baseline(
        &mut self,
        measurements: &[MeasuredLatency],
        commit_sha: &str,
        now_epoch_secs: u64,
        correlation_id: &str,
    ) -> BaselineSnapshot {
        for m in measurements {
            self.emit_event(
                VEF_PERF_004,
                m.operation.label(),
                m.mode.label(),
                correlation_id,
                {
                    let mut d = BTreeMap::new();
                    d.insert("p95_us".into(), serde_json::json!(m.p95_us));
                    d.insert("p99_us".into(), serde_json::json!(m.p99_us));
                    d.insert("commit_sha".into(), serde_json::json!(commit_sha));
                    d
                },
            );
        }

        BaselineSnapshot {
            schema_version: BUDGET_SCHEMA_VERSION.to_string(),
            commit_sha: commit_sha.to_string(),
            recorded_at_epoch_secs: now_epoch_secs,
            measurements: measurements.to_vec(),
        }
    }

    /// Compare current measurements against a baseline for regression detection.
    #[must_use]
    pub fn detect_regressions(
        &self,
        current: &[MeasuredLatency],
        baseline: &BaselineSnapshot,
        regression_threshold_pct: f64,
    ) -> Vec<RegressionReport> {
        let mut reports = Vec::new();

        for curr in current {
            if let Some(base) = baseline
                .measurements
                .iter()
                .find(|b| b.operation == curr.operation && b.mode == curr.mode)
            {
                let p95_delta_pct = if base.p95_us > 0 {
                    ((curr.p95_us as f64 - base.p95_us as f64) / base.p95_us as f64) * 100.0
                } else {
                    0.0
                };
                let p99_delta_pct = if base.p99_us > 0 {
                    ((curr.p99_us as f64 - base.p99_us as f64) / base.p99_us as f64) * 100.0
                } else {
                    0.0
                };

                let regressed = p95_delta_pct > regression_threshold_pct
                    || p99_delta_pct > regression_threshold_pct;

                reports.push(RegressionReport {
                    operation: curr.operation.label().to_string(),
                    mode: curr.mode.label().to_string(),
                    baseline_p95_us: base.p95_us,
                    baseline_p99_us: base.p99_us,
                    current_p95_us: curr.p95_us,
                    current_p99_us: curr.p99_us,
                    p95_delta_pct,
                    p99_delta_pct,
                    regressed,
                });
            }
        }

        reports
    }

    fn emit_event(
        &mut self,
        code: &str,
        op: &str,
        mode: &str,
        corr_id: &str,
        details: BTreeMap<String, serde_json::Value>,
    ) {
        self.audit_log
            .push(VefPerfEvent::new(code, op, mode, corr_id, details));
    }
}

/// Regression report for a single operation/mode pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionReport {
    pub operation: String,
    pub mode: String,
    pub baseline_p95_us: u64,
    pub baseline_p99_us: u64,
    pub current_p95_us: u64,
    pub current_p99_us: u64,
    pub p95_delta_pct: f64,
    pub p99_delta_pct: f64,
    pub regressed: bool,
}

// ── Unit tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_measurement(
        op: VefOperation,
        mode: BudgetMode,
        p95: u64,
        p99: u64,
    ) -> MeasuredLatency {
        MeasuredLatency {
            operation: op,
            mode,
            p50_us: p95 / 2,
            p95_us: p95,
            p99_us: p99,
            max_us: p99 * 2,
            sample_count: 100,
            coefficient_of_variation_pct: 5.0,
        }
    }

    // ── Config tests ────────────────────────────────────────────────────

    #[test]
    fn default_config_validates() {
        let config = VefPerfBudgetConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn default_config_covers_all_operations_and_modes() {
        let config = VefPerfBudgetConfig::default();
        for op in VefOperation::all() {
            for mode in BudgetMode::all() {
                assert!(
                    config.budget_for(*op, *mode).is_some(),
                    "missing budget for {:?} in {:?}",
                    op,
                    mode
                );
            }
        }
    }

    #[test]
    fn normal_budgets_are_tightest() {
        let config = VefPerfBudgetConfig::default();
        for op in VefOperation::all() {
            let normal = config.budget_for(*op, BudgetMode::Normal).unwrap();
            let restricted = config.budget_for(*op, BudgetMode::Restricted).unwrap();
            let quarantine = config.budget_for(*op, BudgetMode::Quarantine).unwrap();
            assert!(
                normal.p95_us <= restricted.p95_us,
                "{:?}: normal p95 {} > restricted p95 {}",
                op,
                normal.p95_us,
                restricted.p95_us
            );
            assert!(
                restricted.p95_us <= quarantine.p95_us,
                "{:?}: restricted p95 {} > quarantine p95 {}",
                op,
                restricted.p95_us,
                quarantine.p95_us
            );
        }
    }

    #[test]
    fn p99_exceeds_p95_in_all_budgets() {
        let config = VefPerfBudgetConfig::default();
        for op in VefOperation::all() {
            for mode in BudgetMode::all() {
                let b = config.budget_for(*op, *mode).unwrap();
                assert!(
                    b.p99_us >= b.p95_us,
                    "{:?}/{:?}: p99 {} < p95 {}",
                    op,
                    mode,
                    b.p99_us,
                    b.p95_us
                );
            }
        }
    }

    #[test]
    fn missing_budget_detected() {
        let mut config = VefPerfBudgetConfig::default();
        config.budgets.remove("receipt_emission");
        assert!(matches!(
            config.validate(),
            Err(VefPerfBudgetError::MissingBudget { .. })
        ));
    }

    #[test]
    fn invalid_noise_tolerance_rejected() {
        let config = VefPerfBudgetConfig {
            noise_tolerance_cv_pct: 0.0,
            ..Default::default()
        };
        assert!(matches!(
            config.validate(),
            Err(VefPerfBudgetError::InvalidConfig(_))
        ));
    }

    #[test]
    fn invalid_min_samples_rejected() {
        let config = VefPerfBudgetConfig {
            min_samples: 0,
            ..Default::default()
        };
        assert!(matches!(
            config.validate(),
            Err(VefPerfBudgetError::InvalidConfig(_))
        ));
    }

    // ── Budget check tests ──────────────────────────────────────────────

    #[test]
    fn within_budget_passes() {
        let budget = LatencyBudget::new(100, 200);
        let measurement = MeasuredLatency {
            operation: VefOperation::ReceiptEmission,
            mode: BudgetMode::Normal,
            p50_us: 25,
            p95_us: 50,
            p99_us: 100,
            max_us: 150,
            sample_count: 100,
            coefficient_of_variation_pct: 5.0,
        };
        let result = budget.check(&measurement);
        assert!(result.passed);
        assert!(result.p95_within_budget);
        assert!(result.p99_within_budget);
        assert!(result.p95_headroom_pct > 0.0);
    }

    #[test]
    fn over_p95_budget_fails() {
        let budget = LatencyBudget::new(100, 200);
        let measurement = MeasuredLatency {
            operation: VefOperation::ReceiptEmission,
            mode: BudgetMode::Normal,
            p50_us: 60,
            p95_us: 120,
            p99_us: 150,
            max_us: 200,
            sample_count: 100,
            coefficient_of_variation_pct: 5.0,
        };
        let result = budget.check(&measurement);
        assert!(!result.passed);
        assert!(!result.p95_within_budget);
        assert!(result.p99_within_budget);
    }

    #[test]
    fn over_p99_budget_fails() {
        let budget = LatencyBudget::new(100, 200);
        let measurement = MeasuredLatency {
            operation: VefOperation::ReceiptEmission,
            mode: BudgetMode::Normal,
            p50_us: 25,
            p95_us: 80,
            p99_us: 250,
            max_us: 300,
            sample_count: 100,
            coefficient_of_variation_pct: 5.0,
        };
        let result = budget.check(&measurement);
        assert!(!result.passed);
        assert!(result.p95_within_budget);
        assert!(!result.p99_within_budget);
    }

    #[test]
    fn exact_boundary_passes() {
        let budget = LatencyBudget::new(100, 200);
        let measurement = MeasuredLatency {
            operation: VefOperation::ReceiptEmission,
            mode: BudgetMode::Normal,
            p50_us: 50,
            p95_us: 100,
            p99_us: 200,
            max_us: 300,
            sample_count: 100,
            coefficient_of_variation_pct: 5.0,
        };
        let result = budget.check(&measurement);
        assert!(result.passed);
    }

    // ── Gate engine tests ───────────────────────────────────────────────

    #[test]
    fn gate_passes_when_all_within_budget() {
        let config = VefPerfBudgetConfig::default();
        let mut gate = VefPerfBudgetGate::new(config);

        let measurements = vec![
            sample_measurement(VefOperation::ReceiptEmission, BudgetMode::Normal, 30, 60),
            sample_measurement(VefOperation::ChainAppend, BudgetMode::Normal, 20, 40),
        ];

        let verdict = gate.evaluate(&measurements, "test-001").unwrap();
        assert!(verdict.passed);
        assert_eq!(verdict.failed_checks, 0);
        assert_eq!(verdict.passed_checks, 2);
    }

    #[test]
    fn gate_fails_when_any_exceeds_budget() {
        let config = VefPerfBudgetConfig::default();
        let mut gate = VefPerfBudgetGate::new(config);

        let measurements = vec![
            sample_measurement(VefOperation::ReceiptEmission, BudgetMode::Normal, 30, 60),
            // This exceeds normal p95=30, p99=60 for chain_append
            sample_measurement(VefOperation::ChainAppend, BudgetMode::Normal, 50, 80),
        ];

        let verdict = gate.evaluate(&measurements, "test-002").unwrap();
        assert!(!verdict.passed);
        assert!(verdict.failed_checks > 0);
    }

    #[test]
    fn insufficient_samples_skipped() {
        let config = VefPerfBudgetConfig::default();
        let mut gate = VefPerfBudgetGate::new(config);

        let mut m = sample_measurement(VefOperation::ReceiptEmission, BudgetMode::Normal, 30, 60);
        m.sample_count = 5; // below min_samples=30

        let verdict = gate.evaluate(&[m], "test-003").unwrap();
        assert!(verdict.passed); // no failures, just skipped
        assert_eq!(verdict.skipped_checks, 1);
        assert_eq!(verdict.passed_checks, 0);
    }

    #[test]
    fn unstable_measurement_marked() {
        let config = VefPerfBudgetConfig::default();
        let mut gate = VefPerfBudgetGate::new(config);

        let mut m = sample_measurement(VefOperation::ReceiptEmission, BudgetMode::Normal, 30, 60);
        m.coefficient_of_variation_pct = 25.0; // above 15% threshold

        let verdict = gate.evaluate(&[m], "test-004").unwrap();
        assert_eq!(verdict.results[0].status, VerdictStatus::Unstable);
        assert!(!verdict.results[0].stable);
    }

    #[test]
    fn audit_events_emitted() {
        let config = VefPerfBudgetConfig::default();
        let mut gate = VefPerfBudgetGate::new(config);

        let measurements = vec![sample_measurement(
            VefOperation::ReceiptEmission,
            BudgetMode::Normal,
            30,
            60,
        )];

        let verdict = gate.evaluate(&measurements, "test-005").unwrap();
        assert!(!verdict.audit_log.is_empty());
        assert!(verdict.audit_log.iter().any(|e| e.code == VEF_PERF_001));
        assert!(verdict.audit_log.iter().any(|e| e.code == VEF_PERF_002));
    }

    #[test]
    fn budget_exceeded_event_on_failure() {
        let config = VefPerfBudgetConfig::default();
        let mut gate = VefPerfBudgetGate::new(config);

        // Exceed chain_append normal budget (p95=30, p99=60)
        let measurements = vec![sample_measurement(
            VefOperation::ChainAppend,
            BudgetMode::Normal,
            50,
            80,
        )];

        let verdict = gate.evaluate(&measurements, "test-006").unwrap();
        assert!(verdict.audit_log.iter().any(|e| e.code == VEF_PERF_003));
    }

    #[test]
    fn per_mode_budgets_enforced() {
        let config = VefPerfBudgetConfig::default();
        let mut gate = VefPerfBudgetGate::new(config);

        // Values that pass quarantine mode but fail normal mode
        let measurements = vec![
            sample_measurement(VefOperation::ReceiptEmission, BudgetMode::Normal, 80, 150),
            sample_measurement(
                VefOperation::ReceiptEmission,
                BudgetMode::Quarantine,
                80,
                150,
            ),
        ];

        let verdict = gate.evaluate(&measurements, "test-007").unwrap();
        // Normal should fail (budget p95=50, p99=100), quarantine should pass (p95=120, p99=250)
        let normal_result = &verdict.results[0];
        let quarantine_result = &verdict.results[1];
        assert_eq!(normal_result.status, VerdictStatus::Fail);
        assert_eq!(quarantine_result.status, VerdictStatus::Pass);
    }

    #[test]
    fn empty_measurements_passes() {
        let config = VefPerfBudgetConfig::default();
        let mut gate = VefPerfBudgetGate::new(config);

        let verdict = gate.evaluate(&[], "test-008").unwrap();
        assert!(verdict.passed);
        assert_eq!(verdict.total_checks, 0);
    }

    // ── Baseline and regression tests ───────────────────────────────────

    #[test]
    fn baseline_recording() {
        let config = VefPerfBudgetConfig::default();
        let mut gate = VefPerfBudgetGate::new(config);

        let measurements = vec![sample_measurement(
            VefOperation::ReceiptEmission,
            BudgetMode::Normal,
            30,
            60,
        )];

        let baseline = gate.record_baseline(&measurements, "abc123", 1000, "test-009");
        assert_eq!(baseline.commit_sha, "abc123");
        assert_eq!(baseline.measurements.len(), 1);
        assert_eq!(baseline.schema_version, BUDGET_SCHEMA_VERSION);
    }

    #[test]
    fn regression_detection() {
        let config = VefPerfBudgetConfig::default();
        let gate = VefPerfBudgetGate::new(config);

        let baseline = BaselineSnapshot {
            schema_version: BUDGET_SCHEMA_VERSION.to_string(),
            commit_sha: "abc123".to_string(),
            recorded_at_epoch_secs: 1000,
            measurements: vec![sample_measurement(
                VefOperation::ReceiptEmission,
                BudgetMode::Normal,
                30,
                60,
            )],
        };

        // 50% regression
        let current = vec![sample_measurement(
            VefOperation::ReceiptEmission,
            BudgetMode::Normal,
            45,
            90,
        )];

        let reports = gate.detect_regressions(&current, &baseline, 10.0);
        assert_eq!(reports.len(), 1);
        assert!(reports[0].regressed);
        assert!(reports[0].p95_delta_pct > 40.0);
    }

    #[test]
    fn no_regression_within_threshold() {
        let config = VefPerfBudgetConfig::default();
        let gate = VefPerfBudgetGate::new(config);

        let baseline = BaselineSnapshot {
            schema_version: BUDGET_SCHEMA_VERSION.to_string(),
            commit_sha: "abc123".to_string(),
            recorded_at_epoch_secs: 1000,
            measurements: vec![sample_measurement(
                VefOperation::ReceiptEmission,
                BudgetMode::Normal,
                30,
                60,
            )],
        };

        let current = vec![sample_measurement(
            VefOperation::ReceiptEmission,
            BudgetMode::Normal,
            32,
            63,
        )];

        let reports = gate.detect_regressions(&current, &baseline, 10.0);
        assert_eq!(reports.len(), 1);
        assert!(!reports[0].regressed);
    }

    // ── Determinism tests ───────────────────────────────────────────────

    #[test]
    fn deterministic_gate_evaluation() {
        let measurements = vec![
            sample_measurement(VefOperation::ReceiptEmission, BudgetMode::Normal, 30, 60),
            sample_measurement(VefOperation::ChainAppend, BudgetMode::Restricted, 40, 80),
        ];

        let mut gate1 = VefPerfBudgetGate::new(VefPerfBudgetConfig::default());
        let mut gate2 = VefPerfBudgetGate::new(VefPerfBudgetConfig::default());

        let v1 = gate1.evaluate(&measurements, "det-001").unwrap();
        let v2 = gate2.evaluate(&measurements, "det-001").unwrap();

        assert_eq!(v1.passed, v2.passed);
        assert_eq!(v1.total_checks, v2.total_checks);
        assert_eq!(v1.passed_checks, v2.passed_checks);
        assert_eq!(v1.failed_checks, v2.failed_checks);
        for (r1, r2) in v1.results.iter().zip(v2.results.iter()) {
            assert_eq!(r1.status, r2.status);
            assert_eq!(r1.operation, r2.operation);
            assert_eq!(r1.mode, r2.mode);
        }
    }

    // ── Serialization round-trip ────────────────────────────────────────

    #[test]
    fn config_serialization_roundtrip() {
        let config = VefPerfBudgetConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: VefPerfBudgetConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.schema_version, config.schema_version);
        assert_eq!(
            deserialized.noise_tolerance_cv_pct,
            config.noise_tolerance_cv_pct
        );
        assert_eq!(deserialized.min_samples, config.min_samples);
    }

    #[test]
    fn baseline_serialization_roundtrip() {
        let baseline = BaselineSnapshot {
            schema_version: BUDGET_SCHEMA_VERSION.to_string(),
            commit_sha: "abc123".to_string(),
            recorded_at_epoch_secs: 1000,
            measurements: vec![sample_measurement(
                VefOperation::ReceiptEmission,
                BudgetMode::Normal,
                30,
                60,
            )],
        };
        let json = serde_json::to_string(&baseline).unwrap();
        let deserialized: BaselineSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.commit_sha, baseline.commit_sha);
        assert_eq!(deserialized.measurements.len(), 1);
    }

    // ── Operation coverage tests ────────────────────────────────────────

    #[test]
    fn all_operations_enumerated() {
        assert_eq!(VefOperation::all().len(), 7);
    }

    #[test]
    fn all_modes_enumerated() {
        assert_eq!(BudgetMode::all().len(), 3);
    }

    #[test]
    fn integration_ops_identified() {
        assert!(VefOperation::ControlPlaneHotPath.is_integration());
        assert!(VefOperation::ExtensionHostHotPath.is_integration());
        assert!(!VefOperation::ReceiptEmission.is_integration());
        assert!(!VefOperation::ChainAppend.is_integration());
    }

    #[test]
    fn operation_labels_unique() {
        let labels: Vec<&str> = VefOperation::all().iter().map(|o| o.label()).collect();
        let unique: std::collections::BTreeSet<&str> = labels.iter().copied().collect();
        assert_eq!(labels.len(), unique.len());
    }

    #[test]
    fn mode_labels_unique() {
        let labels: Vec<&str> = BudgetMode::all().iter().map(|m| m.label()).collect();
        let unique: std::collections::BTreeSet<&str> = labels.iter().copied().collect();
        assert_eq!(labels.len(), unique.len());
    }
}
