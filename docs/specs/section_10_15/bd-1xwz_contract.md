# bd-1xwz: Performance Budget Guard for Asupersync Integration Overhead

**Section:** 10.15 — Asupersync-First Integration
**Type:** Performance Gate
**Status:** Delivered

## Purpose

Measure and enforce overhead budgets for asupersync integration primitives
(Cx propagation, epoch validation, evidence emission) on control-plane hot
paths. Regressions fail CI with flamegraph evidence.

## Hot Paths Under Test

| Hot Path | Enum Variant | Baseline Operation | Integrated Operation |
|----------|-------------|-------------------|---------------------|
| Lifecycle FSM | `LifecycleTransition` | `transition(from, to)` | transition + epoch check + evidence emit |
| Health Gate | `HealthGateEvaluation` | `evaluate(checks)` | evaluate + epoch-scoped policy + evidence emit |
| Rollout Persist | `RolloutStateChange` | `persist(state, path)` | persist + epoch-scoped persist + evidence emit |
| Fencing Validate | `FencingTokenOp` | `validate_write(write, lease, time)` | validate + epoch-scoped write + evidence emit |

## Budget Policy (Default)

Machine-readable policy via `BudgetPolicy::default_policy()`:

| Metric | LifecycleTransition | HealthGateEvaluation | RolloutStateChange | FencingTokenOp |
|--------|-------------------|---------------------|-------------------|---------------|
| p95 overhead | ≤ 15% | ≤ 10% | ≤ 12% | ≤ 8% |
| p99 overhead | ≤ 25% | ≤ 20% | ≤ 22% | ≤ 15% |
| Cold-start | ≤ 50 ms | ≤ 30 ms | ≤ 40 ms | ≤ 20 ms |

## Types

| Type | Description |
|------|-------------|
| `HotPath` | Enum: 4 control-plane hot path variants |
| `HotPathBudget` | Per-path p95/p99/cold-start limits |
| `BudgetPolicy` | Collection of budgets + lookup + serialization |
| `MeasurementResult` | Benchmark output with overhead calculation |
| `GateDecision` | Pass or Fail{violations} |
| `OverheadEvent` | Structured log event |
| `OverheadGateSummary` | Aggregate pass/fail counts |
| `OverheadGate` | Stateful gate: evaluate → gate_pass → report |

## Event Codes

- `PRF-001`: Benchmark started for a hot path
- `PRF-002`: Benchmark completed — within budget
- `PRF-003`: Benchmark completed — over budget
- `PRF-004`: Flamegraph captured
- `PRF-005`: Cold-start measurement completed

## Invariants

- **INV-PBG-BUDGET**: Overhead budgets defined in a machine-readable policy
- **INV-PBG-GATE**: Budget violations block the CI gate
- **INV-PBG-FLAMEGRAPH**: Flamegraph evidence captured on every run
- **INV-PBG-COLD-START**: Cold-start measured separately from steady-state

## Key Methods

| Method | Description |
|--------|-------------|
| `OverheadGate::evaluate()` | Evaluate one measurement against budget |
| `OverheadGate::evaluate_batch()` | Evaluate multiple measurements |
| `OverheadGate::gate_pass()` | Check if all results within budget |
| `OverheadGate::summary()` | Aggregate pass/fail summary |
| `OverheadGate::to_csv()` | CSV report for CI artifacts |
| `OverheadGate::to_report()` | JSON report with full detail |
| `MeasurementResult::from_measurements()` | Compute overhead and check budget |

## Artifacts

- Implementation: `crates/franken-node/src/connector/perf_budget_guard.rs`
- Conformance test: `tests/conformance/perf_budget_guard.rs`
- Spec: `docs/specs/section_10_15/bd-1xwz_contract.md`
- Verification: `scripts/check_perf_budget_guard.py`
- Python tests: `tests/test_check_perf_budget_guard.py`
- Overhead report: `artifacts/10.15/integration_overhead_report.csv`

## Dependencies

- Upstream: bd-2g6r (Cx-first signature policy)
- Downstream: bd-20eg (section gate), bd-3qo (execution track epic)
