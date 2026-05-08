# bd-8l9k: Cross-Substrate Contract Tests Verification Summary

**Section:** 10.16 | **Verdict:** PASS | **Date:** 2026-02-22

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Checker checks | 60 | 60 |
| Self-test checks | 18 | 18 |
| Python unit tests | 16 | 16 |
| Rust unit tests | 56 | 56 |
| E2E scenarios | 7 | 7 |

## Implementation

`tests/e2e/adjacent_substrate_flow.rs`

- **Schema version:** e2e-v1.0
- **Substrates:** frankentui, fastapi_rust, sqlmodel_rust, frankensqlite
- **Harness layers:** TestTui, TestService, tempfile-backed TestPersistence, deterministic TestClock
- **Types:** Substrate, TraceContext, TraceTree, FencingToken, AuditLog, StructuredError, ReplaySeed, ReplayResult, ScenarioRunner, ScenarioResult

## E2E Scenarios

1. **Operator status flow** — TUI -> service -> persistence -> TUI
2. **Lease management flow** — TUI -> service -> fencing -> persistence -> TUI
3. **Audit log flow** — action -> service -> persistence -> verifier -> TUI
4. **Error propagation flow** — invalid request -> structured error -> TUI -> audit
5. **Concurrent access flow** — multi-operator -> fencing -> consistency
6. **Trace propagation** — W3C compliant, no orphaned spans, 4 substrates
7. **Replay determinism** — fixed seeds, deterministic test clocks, identical output hashes, and matching persistence state hashes

## Verification Coverage

- File existence: E2E module, mod.rs wiring, spec, report, evidence, summary
- 7 E2E scenarios covering all four substrate planes
- Trace verification: zero orphaned spans across all scenarios
- Replay determinism: identical seeds produce identical hashes
- Persistence evidence: replay report covers frankensqlite and records persistence_state_match + persistence_state_hash_match
- Gate hardening: checker rejects mock/in-memory persistence markers for the cross-substrate persistence harness
- 6 event codes (E2E_SCENARIO_START/PASS/FAIL, E2E_TRACE_ORPHAN_DETECTED, E2E_REPLAY_MISMATCH, E2E_CONCURRENT_CONFLICT)
- 10 error codes (ERR_E2E_* prefix)
- 7 invariants (INV-E2E-* prefix)
- Schema version "e2e-v1.0" declared
- BTreeMap used for deterministic ordering
- Serde derives present
