# bd-3tpg: Canonical All-Point Cancellation Injection Gate

**Section:** 10.15 | **Type:** task | **Priority:** P1

## Overview

Enforces the canonical all-point cancellation injection framework (bd-876n)
across all critical control-plane workflows in franken_node. Every high-impact
protocol must survive cancellation at every await point without obligation leaks,
half-commit outcomes, or quiescence violations.

## Control Workflows (6)

| Workflow | Await Points | Description |
|----------|-------------|-------------|
| connector_lifecycle | 6 | Initialization, health probe, state load, ready signal, shutdown |
| rollout_transition | 5 | Canary check, promote prepare, state commit, notify peers, rollback |
| quarantine_promotion | 5 | Quarantine check, trust verify, promotion commit, audit, notify |
| migration_orchestration | 6 | Schema check, data migrate, validate result, finalize, cleanup, report |
| fencing_acquire | 4 | Token request, epoch validate, token commit, fence activate |
| health_gate_evaluation | 5 | Probe collect, score compute, verdict emit, threshold update, alert |

## Invariants

| ID | Rule |
|----|------|
| INV-CIG-CANONICAL-ONLY | No custom injection logic; uses canonical CancellationInjectionFramework |
| INV-CIG-ALL-WORKFLOWS | Every critical control workflow is registered |
| INV-CIG-FULL-MATRIX | Injection matrix covers every (workflow, await_point) pair |
| INV-CIG-ZERO-FAILURES | A single failure at any injection point fails the gate |
| INV-CIG-LEAK-FREE | No resource leaks after cancellation at any await point |
| INV-CIG-HALFCOMMIT-FREE | No half-commit state after cancellation |
| INV-CIG-QUIESCENCE-SAFE | No quiescence violations after cancellation |
| INV-CIG-REPORT-COMPLETE | Injection report includes per-workflow per-point results |

## Event Codes

| Code | Description |
|------|-------------|
| CIJ-001 | Control workflow registered for cancellation injection |
| CIJ-002 | Cancellation injected at await point |
| CIJ-003 | Post-cancel invariant assertion passed |
| CIJ-004 | Post-cancel invariant assertion failed |
| CIJ-005 | Gate verdict emitted |
| CIJ-006 | Rust lab model exercised and validated |

## Error Codes

| Code | Description |
|------|-------------|
| CIG-ERR-001 | Injection setup failure |
| CIG-ERR-002 | Workflow registry error |
| CIG-ERR-003 | Await point unresolvable |
| CIG-ERR-004 | Obligation leak detected |
| CIG-ERR-005 | Half-commit detected |
| CIG-ERR-006 | Quiescence timeout |

## Acceptance Criteria

- Canonical cancellation injection runs on every critical protocol flow
- No obligation leaks, no half-commit outcomes, no quiescence violations
- Uses canonical 10.14 framework, not custom injection logic
- Every await point in every critical workflow is covered (>=30 total)
- Single failure at any injection point fails the gate
- Gate report consumed by section gate (bd-20eg)

## Artifacts

- `docs/testing/control_cancellation_injection.md` -- Adoption document
- `artifacts/10.15/control_cancel_injection_report.json` -- Adoption report
- `docs/specs/section_10_15/bd-3tpg_contract.md` -- This spec contract
- `scripts/check_control_cancel_injection.py` -- Verification gate
- `tests/test_check_control_cancel_injection.py` -- Unit tests
- `tests/lab/control_cancellation_injection.rs` -- Rust cancellation injection model (31 tests)
- `artifacts/section_10_15/bd-3tpg/verification_evidence.json`
- `artifacts/section_10_15/bd-3tpg/verification_summary.md`
