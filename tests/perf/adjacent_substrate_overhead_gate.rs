//! bd-35l5: Performance overhead gate for adjacent substrate integrations.
//!
//! Measures overhead of each substrate integration (frankentui, frankensqlite,
//! sqlmodel_rust, fastapi_rust) and fails the CI gate when overhead exceeds
//! defined budgets.
//!
//! # Substrates Under Test
//!
//! | Substrate      | Operation                        | Budget p95 |
//! |----------------|----------------------------------|------------|
//! | frankentui     | render_status_panel              | < 5 ms     |
//! | frankentui     | render_tree_view                 | < 8 ms     |
//! | frankensqlite  | fencing_token_write              | < 10 ms    |
//! | frankensqlite  | config_read                      | < 5 ms     |
//! | sqlmodel_rust  | typed_model_serialize            | < 1 ms     |
//! | sqlmodel_rust  | typed_model_deserialize          | < 1 ms     |
//! | fastapi_rust   | middleware_pipeline              | < 3 ms     |
//! | fastapi_rust   | health_check_endpoint            | < 2 ms     |
//!
//! # Event Codes
//!
//! - `PERF_BENCHMARK_START`: Benchmark run initiated
//! - `PERF_BENCHMARK_COMPLETE`: Benchmark run completed
//! - `PERF_BUDGET_PASS`: Operation within budget
//! - `PERF_BUDGET_FAIL`: Operation exceeds budget
//! - `PERF_REGRESSION_DETECTED`: Regression >10% vs baseline
//!
//! # Invariants
//!
//! - **INV-ASO-BUDGET**: Every substrate operation has an explicit latency budget
//! - **INV-ASO-GATE**: Budget violations block the CI gate
//! - **INV-ASO-EVIDENCE**: Before/after timing evidence on every run
//! - **INV-ASO-REGRESSION**: Regressions >25% vs baseline fail the gate

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const PERF_BENCHMARK_START: &str = "PERF_BENCHMARK_START";
    pub const PERF_BENCHMARK_COMPLETE: &str = "PERF_BENCHMARK_COMPLETE";
    pub const PERF_BUDGET_PASS: &str = "PERF_BUDGET_PASS";
    pub const PERF_BUDGET_FAIL: &str = "PERF_BUDGET_FAIL";
    pub const PERF_REGRESSION_DETECTED: &str = "PERF_REGRESSION_DETECTED";
}

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

pub const INV_ASO_BUDGET: &str = "INV-ASO-BUDGET";
pub const INV_ASO_GATE: &str = "INV-ASO-GATE";
pub const INV_ASO_EVIDENCE: &str = "INV-ASO-EVIDENCE";
pub const INV_ASO_REGRESSION: &str = "INV-ASO-REGRESSION";

// ---------------------------------------------------------------------------
// Substrate
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Substrate {
    Frankentui,
    Frankensqlite,
    SqlmodelRust,
    FastapiRust,
}

impl Substrate {
    pub fn all() -> &'static [Substrate] {
        &[
            Substrate::Frankentui,
            Substrate::Frankensqlite,
            Substrate::SqlmodelRust,
            Substrate::FastapiRust,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Substrate::Frankentui => "frankentui",
            Substrate::Frankensqlite => "frankensqlite",
            Substrate::SqlmodelRust => "sqlmodel_rust",
            Substrate::FastapiRust => "fastapi_rust",
        }
    }
}

impl fmt::Display for Substrate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// Operation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Operation {
    pub substrate: Substrate,
    pub name: String,
    pub budget_ms: f64,
}

// ---------------------------------------------------------------------------
// Default budget definitions
// ---------------------------------------------------------------------------

pub fn default_operations() -> Vec<Operation> {
    vec![
        Operation {
            substrate: Substrate::Frankentui,
            name: "render_status_panel".into(),
            budget_ms: 5.0,
        },
        Operation {
            substrate: Substrate::Frankentui,
            name: "render_tree_view".into(),
            budget_ms: 8.0,
        },
        Operation {
            substrate: Substrate::Frankensqlite,
            name: "fencing_token_write".into(),
            budget_ms: 10.0,
        },
        Operation {
            substrate: Substrate::Frankensqlite,
            name: "config_read".into(),
            budget_ms: 5.0,
        },
        Operation {
            substrate: Substrate::SqlmodelRust,
            name: "typed_model_serialize".into(),
            budget_ms: 1.0,
        },
        Operation {
            substrate: Substrate::SqlmodelRust,
            name: "typed_model_deserialize".into(),
            budget_ms: 1.0,
        },
        Operation {
            substrate: Substrate::FastapiRust,
            name: "middleware_pipeline".into(),
            budget_ms: 3.0,
        },
        Operation {
            substrate: Substrate::FastapiRust,
            name: "health_check_endpoint".into(),
            budget_ms: 2.0,
        },
    ]
}

// ---------------------------------------------------------------------------
// MeasurementRecord
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeasurementRecord {
    pub substrate: Substrate,
    pub operation: String,
    pub budget_ms: f64,
    pub measured_p50_ms: f64,
    pub measured_p95_ms: f64,
    pub measured_p99_ms: f64,
    pub baseline_p50_ms: f64,
    pub within_budget: bool,
    pub regression_detected: bool,
    pub regression_pct: f64,
}

impl MeasurementRecord {
    pub fn from_benchmark(
        op: &Operation,
        measured_p50_ms: f64,
        measured_p95_ms: f64,
        measured_p99_ms: f64,
        baseline_p50_ms: f64,
    ) -> Self {
        let within_budget = measured_p95_ms <= op.budget_ms;
        let regression_pct = if baseline_p50_ms > 0.0 {
            ((measured_p50_ms - baseline_p50_ms) / baseline_p50_ms) * 100.0
        } else {
            0.0
        };
        let regression_detected = regression_pct > 10.0;

        Self {
            substrate: op.substrate,
            operation: op.name.clone(),
            budget_ms: op.budget_ms,
            measured_p50_ms,
            measured_p95_ms,
            measured_p99_ms,
            baseline_p50_ms,
            within_budget,
            regression_detected,
            regression_pct,
        }
    }

    pub fn to_csv_row(&self) -> String {
        let status = if self.within_budget { "pass" } else { "fail" };
        format!(
            "{},{},{:.1},{:.3},{:.3},{:.3},{},{:.3},{}",
            self.substrate.label(),
            self.operation,
            self.budget_ms,
            self.measured_p50_ms,
            self.measured_p95_ms,
            self.measured_p99_ms,
            status,
            self.baseline_p50_ms,
            self.regression_detected,
        )
    }

    pub fn is_hard_regression(&self) -> bool {
        self.regression_pct > 25.0
    }
}

// ---------------------------------------------------------------------------
// GateDecision
// ---------------------------------------------------------------------------

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
            Self::Fail { violations } => write!(f, "FAIL ({} violations)", violations.len()),
        }
    }
}

// ---------------------------------------------------------------------------
// PerfEvent
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfEvent {
    pub code: String,
    pub substrate: String,
    pub operation: String,
    pub detail: String,
    pub run_id: String,
}

// ---------------------------------------------------------------------------
// OverheadGateSummary
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OverheadGateSummary {
    pub total: usize,
    pub within_budget: usize,
    pub over_budget: usize,
    pub regressions: usize,
    pub hard_regressions: usize,
}

impl OverheadGateSummary {
    pub fn gate_pass(&self) -> bool {
        self.over_budget == 0 && self.hard_regressions == 0 && self.total > 0
    }
}

impl fmt::Display for OverheadGateSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SubstrateOverheadGate: total={}, pass={}, fail={}, regressions={}",
            self.total, self.within_budget, self.over_budget, self.regressions
        )
    }
}

// ---------------------------------------------------------------------------
// SubstrateOverheadGate
// ---------------------------------------------------------------------------

pub struct SubstrateOverheadGate {
    #[allow(dead_code)]
    operations: Vec<Operation>,
    records: Vec<MeasurementRecord>,
    events: Vec<PerfEvent>,
    run_id: String,
}

impl SubstrateOverheadGate {
    pub fn new(operations: Vec<Operation>, run_id: String) -> Self {
        Self {
            operations,
            records: Vec::new(),
            events: Vec::new(),
            run_id,
        }
    }

    pub fn with_defaults(run_id: String) -> Self {
        Self::new(default_operations(), run_id)
    }

    pub fn evaluate(&mut self, record: MeasurementRecord) -> GateDecision {
        self.emit_event(
            event_codes::PERF_BENCHMARK_START,
            &record,
            format!(
                "Benchmark started for {}/{}",
                record.substrate.label(),
                record.operation
            ),
        );

        let mut violations = Vec::new();

        if !record.within_budget {
            violations.push(format!(
                "{}/{}: p95 {:.3}ms > budget {:.1}ms",
                record.substrate.label(),
                record.operation,
                record.measured_p95_ms,
                record.budget_ms
            ));
            self.emit_event(
                event_codes::PERF_BUDGET_FAIL,
                &record,
                format!(
                    "Over budget: p95={:.3}ms > {:.1}ms",
                    record.measured_p95_ms, record.budget_ms
                ),
            );
        } else {
            self.emit_event(
                event_codes::PERF_BUDGET_PASS,
                &record,
                format!(
                    "Within budget: p95={:.3}ms <= {:.1}ms",
                    record.measured_p95_ms, record.budget_ms
                ),
            );
        }

        if record.regression_detected {
            self.emit_event(
                event_codes::PERF_REGRESSION_DETECTED,
                &record,
                format!("Regression: {:.1}% vs baseline", record.regression_pct),
            );
            if record.is_hard_regression() {
                violations.push(format!(
                    "{}/{}: regression {:.1}% > 25% threshold",
                    record.substrate.label(),
                    record.operation,
                    record.regression_pct
                ));
            }
        }

        self.emit_event(
            event_codes::PERF_BENCHMARK_COMPLETE,
            &record,
            format!(
                "Benchmark complete for {}/{}",
                record.substrate.label(),
                record.operation
            ),
        );

        self.records.push(record);

        if violations.is_empty() {
            GateDecision::Pass
        } else {
            GateDecision::Fail { violations }
        }
    }

    pub fn evaluate_batch(&mut self, records: Vec<MeasurementRecord>) -> Vec<GateDecision> {
        records.into_iter().map(|r| self.evaluate(r)).collect()
    }

    pub fn gate_pass(&self) -> bool {
        !self.records.is_empty()
            && self.records.iter().all(|r| r.within_budget)
            && !self.records.iter().any(|r| r.is_hard_regression())
    }

    pub fn summary(&self) -> OverheadGateSummary {
        OverheadGateSummary {
            total: self.records.len(),
            within_budget: self.records.iter().filter(|r| r.within_budget).count(),
            over_budget: self.records.iter().filter(|r| !r.within_budget).count(),
            regressions: self
                .records
                .iter()
                .filter(|r| r.regression_detected)
                .count(),
            hard_regressions: self
                .records
                .iter()
                .filter(|r| r.is_hard_regression())
                .count(),
        }
    }

    #[allow(dead_code)]
    pub fn operations(&self) -> &[Operation] {
        &self.operations
    }

    pub fn records(&self) -> &[MeasurementRecord] {
        &self.records
    }

    pub fn events(&self) -> &[PerfEvent] {
        &self.events
    }

    pub fn take_events(&mut self) -> Vec<PerfEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn to_csv(&self) -> String {
        let header = "substrate,operation,budget_ms,measured_p50_ms,measured_p95_ms,measured_p99_ms,status,baseline_p50_ms,regression_detected";
        let rows: Vec<String> = self.records.iter().map(|r| r.to_csv_row()).collect();
        format!("{}\n{}", header, rows.join("\n"))
    }

    pub fn to_report(&self) -> serde_json::Value {
        let summary = self.summary();
        serde_json::json!({
            "bead_id": "bd-35l5",
            "section": "10.16",
            "run_id": self.run_id,
            "gate_pass": summary.gate_pass(),
            "summary": {
                "total": summary.total,
                "within_budget": summary.within_budget,
                "over_budget": summary.over_budget,
                "regressions": summary.regressions,
                "hard_regressions": summary.hard_regressions,
            },
            "records": self.records,
        })
    }

    fn emit_event(&mut self, code: &str, record: &MeasurementRecord, detail: String) {
        self.events.push(PerfEvent {
            code: code.to_string(),
            substrate: record.substrate.label().to_string(),
            operation: record.operation.clone(),
            detail,
            run_id: self.run_id.clone(),
        });
    }
}

impl Default for SubstrateOverheadGate {
    fn default() -> Self {
        Self::with_defaults("default-run".into())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_op(substrate: Substrate, name: &str, budget_ms: f64) -> Operation {
        Operation {
            substrate,
            name: name.into(),
            budget_ms,
        }
    }

    fn within_budget_record(op: &Operation) -> MeasurementRecord {
        MeasurementRecord::from_benchmark(
            op,
            op.budget_ms * 0.5, // p50
            op.budget_ms * 0.8, // p95 (within budget)
            op.budget_ms * 0.9, // p99
            op.budget_ms * 0.5, // baseline (no regression)
        )
    }

    fn over_budget_record(op: &Operation) -> MeasurementRecord {
        MeasurementRecord::from_benchmark(
            op,
            op.budget_ms * 1.5,
            op.budget_ms * 2.0,
            op.budget_ms * 2.5,
            op.budget_ms * 0.5,
        )
    }

    // ── Substrate ───────────────────────────────────────────────

    #[test]
    fn test_substrate_all() {
        assert_eq!(Substrate::all().len(), 4);
    }

    #[test]
    fn test_substrate_labels() {
        assert_eq!(Substrate::Frankentui.label(), "frankentui");
        assert_eq!(Substrate::Frankensqlite.label(), "frankensqlite");
        assert_eq!(Substrate::SqlmodelRust.label(), "sqlmodel_rust");
        assert_eq!(Substrate::FastapiRust.label(), "fastapi_rust");
    }

    #[test]
    fn test_substrate_display() {
        assert_eq!(format!("{}", Substrate::Frankentui), "frankentui");
    }

    #[test]
    fn test_substrate_serde_roundtrip() {
        for s in Substrate::all() {
            let json = serde_json::to_string(s).unwrap();
            let parsed: Substrate = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, *s);
        }
    }

    // ── Operations ──────────────────────────────────────────────

    #[test]
    fn test_default_operations_count() {
        assert_eq!(default_operations().len(), 8);
    }

    #[test]
    fn test_default_operations_all_substrates() {
        let ops = default_operations();
        for substrate in Substrate::all() {
            let count = ops.iter().filter(|o| o.substrate == *substrate).count();
            assert!(
                count >= 2,
                "Substrate {} has {} operations",
                substrate,
                count
            );
        }
    }

    #[test]
    fn test_default_operations_budgets_positive() {
        for op in default_operations() {
            assert!(
                op.budget_ms > 0.0,
                "Budget for {}/{} must be positive",
                op.substrate,
                op.name
            );
        }
    }

    // ── MeasurementRecord ───────────────────────────────────────

    #[test]
    fn test_measurement_within_budget() {
        let op = make_op(Substrate::Frankentui, "render", 5.0);
        let r = MeasurementRecord::from_benchmark(&op, 2.0, 4.0, 4.5, 2.0);
        assert!(r.within_budget);
        assert!(!r.regression_detected);
    }

    #[test]
    fn test_measurement_over_budget() {
        let op = make_op(Substrate::Frankentui, "render", 5.0);
        let r = MeasurementRecord::from_benchmark(&op, 6.0, 8.0, 9.0, 2.0);
        assert!(!r.within_budget);
    }

    #[test]
    fn test_measurement_regression_detected() {
        let op = make_op(Substrate::Frankentui, "render", 50.0);
        let r = MeasurementRecord::from_benchmark(&op, 2.5, 4.0, 4.5, 2.0);
        assert!(r.regression_detected); // 25% > 10%
        assert!(!r.is_hard_regression()); // 25% = 25%, not > 25%
    }

    #[test]
    fn test_measurement_hard_regression() {
        let op = make_op(Substrate::Frankentui, "render", 50.0);
        let r = MeasurementRecord::from_benchmark(&op, 3.0, 4.0, 4.5, 2.0);
        assert!(r.is_hard_regression()); // 50% > 25%
    }

    #[test]
    fn test_measurement_zero_baseline() {
        let op = make_op(Substrate::Frankentui, "render", 5.0);
        let r = MeasurementRecord::from_benchmark(&op, 2.0, 4.0, 4.5, 0.0);
        assert_eq!(r.regression_pct, 0.0);
        assert!(!r.regression_detected);
    }

    #[test]
    fn test_measurement_csv_row() {
        let op = make_op(Substrate::Frankentui, "render", 5.0);
        let r = within_budget_record(&op);
        let row = r.to_csv_row();
        assert!(row.starts_with("frankentui,render,"));
        assert!(row.contains("pass"));
    }

    #[test]
    fn test_measurement_serde_roundtrip() {
        let op = make_op(Substrate::Frankentui, "render", 5.0);
        let r = within_budget_record(&op);
        let json = serde_json::to_string(&r).unwrap();
        let parsed: MeasurementRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.substrate, r.substrate);
        assert_eq!(parsed.within_budget, r.within_budget);
    }

    // ── GateDecision ────────────────────────────────────────────

    #[test]
    fn test_gate_decision_pass() {
        assert!(GateDecision::Pass.is_pass());
        assert!(!GateDecision::Pass.is_fail());
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
    }

    #[test]
    fn test_gate_decision_serde_roundtrip() {
        let d = GateDecision::Pass;
        let json = serde_json::to_string(&d).unwrap();
        let parsed: GateDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, d);
    }

    // ── OverheadGateSummary ─────────────────────────────────────

    #[test]
    fn test_summary_gate_pass() {
        let s = OverheadGateSummary {
            total: 8,
            within_budget: 8,
            over_budget: 0,
            regressions: 0,
            hard_regressions: 0,
        };
        assert!(s.gate_pass());
    }

    #[test]
    fn test_summary_gate_fail_over_budget() {
        let s = OverheadGateSummary {
            total: 8,
            within_budget: 7,
            over_budget: 1,
            regressions: 0,
            hard_regressions: 0,
        };
        assert!(!s.gate_pass());
    }

    #[test]
    fn test_summary_gate_fail_hard_regression() {
        let s = OverheadGateSummary {
            total: 8,
            within_budget: 8,
            over_budget: 0,
            regressions: 1,
            hard_regressions: 1,
        };
        assert!(!s.gate_pass());
    }

    #[test]
    fn test_summary_gate_fail_empty() {
        let s = OverheadGateSummary {
            total: 0,
            within_budget: 0,
            over_budget: 0,
            regressions: 0,
            hard_regressions: 0,
        };
        assert!(!s.gate_pass());
    }

    #[test]
    fn test_summary_display() {
        let s = OverheadGateSummary {
            total: 8,
            within_budget: 7,
            over_budget: 1,
            regressions: 1,
            hard_regressions: 0,
        };
        let display = s.to_string();
        assert!(display.contains("8"));
        assert!(display.contains("fail=1"));
    }

    // ── SubstrateOverheadGate ───────────────────────────────────

    #[test]
    fn test_gate_evaluate_within_budget() {
        let op = make_op(Substrate::Frankentui, "render", 5.0);
        let mut gate = SubstrateOverheadGate::with_defaults("test-run".into());
        let r = within_budget_record(&op);
        let d = gate.evaluate(r);
        assert!(d.is_pass());
    }

    #[test]
    fn test_gate_evaluate_over_budget() {
        let op = make_op(Substrate::Frankentui, "render", 5.0);
        let mut gate = SubstrateOverheadGate::with_defaults("test-run".into());
        let r = over_budget_record(&op);
        let d = gate.evaluate(r);
        assert!(d.is_fail());
    }

    #[test]
    fn test_gate_pass_all_within() {
        let mut gate = SubstrateOverheadGate::with_defaults("test-run".into());
        for op in default_operations() {
            gate.evaluate(within_budget_record(&op));
        }
        assert!(gate.gate_pass());
    }

    #[test]
    fn test_gate_fail_one_over() {
        let mut gate = SubstrateOverheadGate::with_defaults("test-run".into());
        let ops = default_operations();
        gate.evaluate(within_budget_record(&ops[0]));
        gate.evaluate(over_budget_record(&ops[1]));
        assert!(!gate.gate_pass());
    }

    #[test]
    fn test_gate_evaluate_batch() {
        let mut gate = SubstrateOverheadGate::with_defaults("test-run".into());
        let ops = default_operations();
        let records: Vec<_> = ops.iter().map(within_budget_record).collect();
        let decisions = gate.evaluate_batch(records);
        assert_eq!(decisions.len(), 8);
        assert!(decisions.iter().all(|d| d.is_pass()));
    }

    #[test]
    fn test_gate_evaluate_batch_mixed() {
        let mut gate = SubstrateOverheadGate::with_defaults("test-run".into());
        let ops = default_operations();
        let records = vec![within_budget_record(&ops[0]), over_budget_record(&ops[1])];
        let decisions = gate.evaluate_batch(records);
        assert!(decisions[0].is_pass());
        assert!(decisions[1].is_fail());
    }

    // ── Events ──────────────────────────────────────────────────

    #[test]
    fn test_evaluate_emits_benchmark_start() {
        let op = make_op(Substrate::Frankentui, "render", 5.0);
        let mut gate = SubstrateOverheadGate::with_defaults("test-run".into());
        gate.evaluate(within_budget_record(&op));
        let starts: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == event_codes::PERF_BENCHMARK_START)
            .collect();
        assert_eq!(starts.len(), 1);
    }

    #[test]
    fn test_evaluate_emits_benchmark_complete() {
        let op = make_op(Substrate::Frankentui, "render", 5.0);
        let mut gate = SubstrateOverheadGate::with_defaults("test-run".into());
        gate.evaluate(within_budget_record(&op));
        let completes: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == event_codes::PERF_BENCHMARK_COMPLETE)
            .collect();
        assert_eq!(completes.len(), 1);
    }

    #[test]
    fn test_evaluate_within_emits_budget_pass() {
        let op = make_op(Substrate::Frankentui, "render", 5.0);
        let mut gate = SubstrateOverheadGate::with_defaults("test-run".into());
        gate.evaluate(within_budget_record(&op));
        let passes: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == event_codes::PERF_BUDGET_PASS)
            .collect();
        assert_eq!(passes.len(), 1);
    }

    #[test]
    fn test_evaluate_over_emits_budget_fail() {
        let op = make_op(Substrate::Frankentui, "render", 5.0);
        let mut gate = SubstrateOverheadGate::with_defaults("test-run".into());
        gate.evaluate(over_budget_record(&op));
        let fails: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == event_codes::PERF_BUDGET_FAIL)
            .collect();
        assert_eq!(fails.len(), 1);
    }

    #[test]
    fn test_evaluate_regression_emits_event() {
        let op = make_op(Substrate::Frankentui, "render", 50.0);
        let mut gate = SubstrateOverheadGate::with_defaults("test-run".into());
        let r = MeasurementRecord::from_benchmark(&op, 3.0, 4.0, 4.5, 2.0);
        gate.evaluate(r);
        let regressions: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == event_codes::PERF_REGRESSION_DETECTED)
            .collect();
        assert_eq!(regressions.len(), 1);
    }

    #[test]
    fn test_event_has_run_id() {
        let op = make_op(Substrate::Frankentui, "render", 5.0);
        let mut gate = SubstrateOverheadGate::with_defaults("my-run-42".into());
        gate.evaluate(within_budget_record(&op));
        assert!(gate.events().iter().all(|e| e.run_id == "my-run-42"));
    }

    #[test]
    fn test_take_events_drains() {
        let op = make_op(Substrate::Frankentui, "render", 5.0);
        let mut gate = SubstrateOverheadGate::with_defaults("test-run".into());
        gate.evaluate(within_budget_record(&op));
        assert!(!gate.events().is_empty());
        let events = gate.take_events();
        assert!(!events.is_empty());
        assert!(gate.events().is_empty());
    }

    // ── CSV ─────────────────────────────────────────────────────

    #[test]
    fn test_csv_header() {
        let gate = SubstrateOverheadGate::default();
        let csv = gate.to_csv();
        assert!(csv.starts_with("substrate,operation,budget_ms"));
    }

    #[test]
    fn test_csv_with_results() {
        let mut gate = SubstrateOverheadGate::with_defaults("test-run".into());
        for op in default_operations() {
            gate.evaluate(within_budget_record(&op));
        }
        let csv = gate.to_csv();
        let lines: Vec<_> = csv.lines().collect();
        assert_eq!(lines.len(), 9); // header + 8 rows
    }

    // ── JSON report ─────────────────────────────────────────────

    #[test]
    fn test_report_structure() {
        let mut gate = SubstrateOverheadGate::with_defaults("test-run".into());
        let op = make_op(Substrate::Frankentui, "render", 5.0);
        gate.evaluate(within_budget_record(&op));
        let report = gate.to_report();
        assert_eq!(report["bead_id"], "bd-35l5");
        assert_eq!(report["section"], "10.16");
        assert!(report["gate_pass"].as_bool().unwrap());
    }

    #[test]
    fn test_report_records() {
        let mut gate = SubstrateOverheadGate::with_defaults("test-run".into());
        for op in default_operations() {
            gate.evaluate(within_budget_record(&op));
        }
        let report = gate.to_report();
        assert_eq!(report["records"].as_array().unwrap().len(), 8);
    }

    // ── Default ─────────────────────────────────────────────────

    #[test]
    fn test_default_gate() {
        let gate = SubstrateOverheadGate::default();
        assert!(gate.records().is_empty());
        assert!(gate.events().is_empty());
        assert!(!gate.gate_pass());
    }

    // ── Summary ─────────────────────────────────────────────────

    #[test]
    fn test_summary_all_within() {
        let mut gate = SubstrateOverheadGate::with_defaults("test-run".into());
        for op in default_operations() {
            gate.evaluate(within_budget_record(&op));
        }
        let s = gate.summary();
        assert_eq!(s.total, 8);
        assert_eq!(s.within_budget, 8);
        assert_eq!(s.over_budget, 0);
        assert!(s.gate_pass());
    }

    #[test]
    fn test_summary_mixed() {
        let mut gate = SubstrateOverheadGate::with_defaults("test-run".into());
        let ops = default_operations();
        gate.evaluate(within_budget_record(&ops[0]));
        gate.evaluate(over_budget_record(&ops[1]));
        let s = gate.summary();
        assert_eq!(s.total, 2);
        assert_eq!(s.within_budget, 1);
        assert_eq!(s.over_budget, 1);
    }

    // ── Event codes defined ─────────────────────────────────────

    #[test]
    fn test_event_codes_defined() {
        assert!(!event_codes::PERF_BENCHMARK_START.is_empty());
        assert!(!event_codes::PERF_BENCHMARK_COMPLETE.is_empty());
        assert!(!event_codes::PERF_BUDGET_PASS.is_empty());
        assert!(!event_codes::PERF_BUDGET_FAIL.is_empty());
        assert!(!event_codes::PERF_REGRESSION_DETECTED.is_empty());
    }

    // ── Invariant constants ─────────────────────────────────────

    #[test]
    fn test_invariant_constants_defined() {
        assert!(!INV_ASO_BUDGET.is_empty());
        assert!(!INV_ASO_GATE.is_empty());
        assert!(!INV_ASO_EVIDENCE.is_empty());
        assert!(!INV_ASO_REGRESSION.is_empty());
    }

    // ── PerfEvent serde ─────────────────────────────────────────

    #[test]
    fn test_perf_event_serde() {
        let event = PerfEvent {
            code: "PERF_BENCHMARK_START".into(),
            substrate: "frankentui".into(),
            operation: "render".into(),
            detail: "test".into(),
            run_id: "run-1".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: PerfEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.code, "PERF_BENCHMARK_START");
    }

    // ── Determinism ─────────────────────────────────────────────

    #[test]
    fn test_determinism_identical_measurements() {
        let op = make_op(Substrate::Frankentui, "render", 5.0);
        let results: Vec<_> = (0..10)
            .map(|_| MeasurementRecord::from_benchmark(&op, 2.0, 4.0, 4.5, 2.0))
            .collect();
        let first = &results[0];
        for r in &results[1..] {
            assert_eq!(r.within_budget, first.within_budget);
            assert_eq!(r.regression_pct, first.regression_pct);
        }
    }

    // ── Fail violations ─────────────────────────────────────────

    #[test]
    fn test_fail_has_violation_details() {
        let op = make_op(Substrate::Frankentui, "render", 5.0);
        let mut gate = SubstrateOverheadGate::with_defaults("test-run".into());
        let r = over_budget_record(&op);
        let d = gate.evaluate(r);
        if let GateDecision::Fail { violations } = d {
            assert!(!violations.is_empty());
            assert!(violations[0].contains("frankentui"));
        } else {
            panic!("Expected Fail");
        }
    }

    // ── Hard regression fails gate ──────────────────────────────

    #[test]
    fn test_hard_regression_fails_gate() {
        let op = make_op(Substrate::Frankentui, "render", 50.0);
        let mut gate = SubstrateOverheadGate::with_defaults("test-run".into());
        // p95 within budget but hard regression
        let r = MeasurementRecord::from_benchmark(&op, 3.0, 4.0, 4.5, 2.0);
        let d = gate.evaluate(r);
        assert!(d.is_fail()); // 50% regression > 25%
        assert!(!gate.gate_pass());
    }

    // ── Soft regression passes gate ─────────────────────────────

    #[test]
    fn test_soft_regression_passes_gate() {
        let op = make_op(Substrate::Frankentui, "render", 50.0);
        let mut gate = SubstrateOverheadGate::with_defaults("test-run".into());
        // 15% regression: detected but not hard
        let r = MeasurementRecord::from_benchmark(&op, 2.3, 4.0, 4.5, 2.0);
        let d = gate.evaluate(r);
        assert!(d.is_pass()); // soft regression doesn't fail
        assert!(gate.gate_pass());
    }
}
