# bd-35l5: Adjacent Substrate Overhead Guardrails

**Section:** 10.16 | **Verdict:** PASS | **Date:** 2026-02-20

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Rust unit tests (perf) | 50 | 50 |
| Python verification checks | 121 | 121 |
| Python unit tests | 39 | 39 |

## Implementation

`tests/perf/adjacent_substrate_overhead_gate.rs`

- **Types:** Substrate (4 variants), Operation, MeasurementRecord, GateDecision (Pass/Fail), PerfEvent, OverheadGateSummary, SubstrateOverheadGate
- **Event codes:** PERF_BENCHMARK_START, PERF_BENCHMARK_COMPLETE, PERF_BUDGET_PASS, PERF_BUDGET_FAIL, PERF_REGRESSION_DETECTED
- **Invariants:** INV-ASO-BUDGET, INV-ASO-GATE, INV-ASO-EVIDENCE, INV-ASO-REGRESSION
- **Substrates:** frankentui, frankensqlite, sqlmodel_rust, fastapi_rust
- **Operations:** 8 (2 per substrate) with explicit p95 budgets
- **Regression thresholds:** >10% warning, >25% gate failure

## Verification Coverage

- File existence (3 files: perf test, spec, overhead CSV)
- Test count (50 Rust tests, minimum 35)
- Serde derives present
- All 7 types, 19 methods, 5 event codes, 4 invariants verified
- All 50 impl tests verified
- Overhead CSV: 8 operations, all pass at p95, no regressions, baselines present
- Spec: 4 substrates, 5 event codes, 4 invariants documented
