# bd-35l5: Performance Overhead Guardrails for Adjacent Substrate Integrations

**Section:** 10.16 — Adjacent Substrate Integration
**Type:** Performance Gate
**Status:** Delivered

## Purpose

Define and enforce overhead budgets for adjacent substrate integrations
(frankentui, frankensqlite, sqlmodel_rust, fastapi_rust) to prevent silent
performance degradation in the franken_node operational kernel.

## Substrates and Operations

| Substrate | Operation | Budget p95 |
|-----------|-----------|------------|
| frankentui | render_status_panel | < 5 ms |
| frankentui | render_tree_view | < 8 ms |
| frankensqlite | fencing_token_write | < 10 ms |
| frankensqlite | config_read | < 5 ms |
| sqlmodel_rust | typed_model_serialize | < 1 ms |
| sqlmodel_rust | typed_model_deserialize | < 1 ms |
| fastapi_rust | middleware_pipeline | < 3 ms |
| fastapi_rust | health_check_endpoint | < 2 ms |

## Types

| Type | Description |
|------|-------------|
| `Substrate` | Enum: 4 adjacent substrate variants |
| `Operation` | Substrate + operation name + budget |
| `MeasurementRecord` | Benchmark output with regression detection |
| `GateDecision` | Pass or Fail{violations} |
| `PerfEvent` | Structured log event with run_id |
| `OverheadGateSummary` | Aggregate pass/fail/regression counts |
| `SubstrateOverheadGate` | Stateful gate: evaluate → gate_pass → report |

## Event Codes

- `PERF_BENCHMARK_START`: Benchmark run initiated
- `PERF_BENCHMARK_COMPLETE`: Benchmark run completed
- `PERF_BUDGET_PASS`: Operation within budget
- `PERF_BUDGET_FAIL`: Operation exceeds budget
- `PERF_REGRESSION_DETECTED`: Regression >10% vs baseline

## Invariants

- **INV-ASO-BUDGET**: Every substrate operation has an explicit latency budget
- **INV-ASO-GATE**: Budget violations block the CI gate
- **INV-ASO-EVIDENCE**: Before/after timing evidence on every run
- **INV-ASO-REGRESSION**: Regressions >25% vs baseline fail the gate

## Regression Thresholds

- > 10% regression vs baseline: warning (PERF_REGRESSION_DETECTED event)
- > 25% regression vs baseline: gate failure

## Artifacts

- Perf test: `tests/perf/adjacent_substrate_overhead_gate.rs`
- Overhead CSV: `artifacts/10.16/adjacent_substrate_overhead_report.csv`
- Spec: `docs/specs/section_10_16/bd-35l5_contract.md`
- Verification: `scripts/check_substrate_overhead.py`
- Python tests: `tests/test_check_substrate_overhead.py`

## Dependencies

- None within 10.16 (logically depends on substrate integrations existing)
- Downstream: bd-10g0 (section gate), bd-n71 (execution track epic)
