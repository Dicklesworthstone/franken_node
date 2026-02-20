# bd-2vl5: Performance and Developer Velocity Doctrine

**Section:** 7 — Performance Doctrine
**Type:** Doctrine Document
**Status:** In Progress

## Core Principles

| ID | Principle | Metric |
|----|-----------|--------|
| PRF-01 | Low startup overhead | Cold-start < 100ms for migration/CI loops |
| PRF-02 | Predictable p99 under churn | p99 latency within budget under extension churn |
| PRF-03 | Bounded security overhead | Security instrumentation < 5% of hot-path budget |
| PRF-04 | Fast migration feedback | Compatibility diff generation < 500ms |

## Candidate High-EV Optimization Levers

| ID | Lever | Owner Track | Profile Gate |
|----|-------|-------------|-------------|
| LEV-01 | Compatibility cache with deterministic invalidation | 10.6 | MS-01 |
| LEV-02 | Lockstep differential harness acceleration | 10.6 | MS-01 |
| LEV-03 | Zero-copy hostcall bridge paths | 10.6 | MS-01 |
| LEV-04 | Batch policy evaluation | 10.5 | MS-01 |
| LEV-05 | Multi-lane scheduler tuning | 10.15 | MS-01 |

## Required Performance Artifacts

| ID | Artifact | Required For |
|----|----------|-------------|
| ART-01 | Baseline reports with reproducible configs | All performance PRs |
| ART-02 | Profile artifacts (flamegraphs/traces) | All optimization PRs |
| ART-03 | Before/after comparison tables | All optimization PRs |
| ART-04 | Compatibility correctness proofs | Tuned path PRs |
| ART-05 | Tail-latency impact notes | Security instrumentation PRs |

## Event Codes

| Code | Level | Meaning |
|------|-------|---------|
| PRF-001 | info | Performance doctrine compliance verified |
| PRF-002 | error | Missing performance artifact |
| PRF-003 | info | Optimization lever profiled |
| PRF-004 | error | p99 budget exceeded |
| PRF-005 | info | Cold-start budget met |

## Invariants

| ID | Statement |
|----|-----------|
| INV-PRF-PRINCIPLES | All 4 core principles have measurable metrics |
| INV-PRF-ARTIFACTS | Performance PRs include all required artifacts |
| INV-PRF-PROFILED | Every optimization has before/after evidence |
| INV-PRF-COMPAT | Tuned paths have compatibility correctness proofs |

## Artifacts

- Doctrine doc: `docs/doctrine/performance_and_velocity.md`
- Spec contract: `docs/specs/section_7/bd-2vl5_contract.md`
- Verification: `scripts/check_performance_doctrine.py`
- Tests: `tests/test_check_performance_doctrine.py`
