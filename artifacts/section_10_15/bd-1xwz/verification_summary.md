# bd-1xwz: Performance Budget Guard

**Section:** 10.15 | **Verdict:** PASS | **Date:** 2026-02-20

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Rust unit tests (impl) | 55 | 55 |
| Rust conformance tests | 20 | 20 |
| Python verification checks | 142 | 142 |
| Python unit tests | 40 | 40 |

## Implementation

`crates/franken-node/src/connector/perf_budget_guard.rs`

- **Types:** HotPath (4 variants), HotPathBudget, BudgetPolicy, MeasurementResult, GateDecision (Pass/Fail), OverheadEvent, OverheadGateSummary, OverheadGate
- **Event codes:** PRF-001 (started), PRF-002 (within budget), PRF-003 (over budget), PRF-004 (flamegraph), PRF-005 (cold-start)
- **Invariants:** INV-PBG-BUDGET, INV-PBG-GATE, INV-PBG-FLAMEGRAPH, INV-PBG-COLD-START
- **Hot paths:** LifecycleTransition, HealthGateEvaluation, RolloutStateChange, FencingTokenOp
- **Key methods:** evaluate(), evaluate_batch(), gate_pass(), summary(), to_csv(), to_report()
- **Budget policy:** Machine-readable JSON with per-path p95/p99/cold-start limits

## Verification Coverage

- File existence (4 files: impl, conformance test, spec, overhead CSV)
- Module registration in connector/mod.rs
- Test counts (55 impl, 20 conformance)
- Serde derives present
- All 8 types, 20 methods, 5 event codes, 4 invariants, 4 hot paths verified
- All 51 impl tests and 20 conformance tests verified
- Overhead CSV: valid header, 4 data rows, all within budget
- Spec: 4 hot paths, 5 event codes, 4 invariants documented
