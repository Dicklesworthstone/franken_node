# bd-3a3q: Verification Summary

## Anytime-Valid Guardrail Monitor Set

**Section:** 10.14 (FrankenSQLite Deep-Mined Expansion)
**Status:** PASS (12/12 checks)
**Agent:** CrimsonCrane (claude-code, claude-opus-4-6)
**Date:** 2026-05-12

## Implementation

- **Module:** `crates/franken-node/src/policy/guardrail_monitor.rs`
- **Spec:** `docs/specs/section_10_14/bd-3a3q_contract.md`
- **Verification:** `scripts/check_guardrail_monitor.py`
- **Test Suite:** `tests/test_check_guardrail_monitor.py` (18 tests)
- **Git xref:** `10f532f3bcb7d988f9d8e868cbdd384ba8828bad` (initial guardrail monitor implementation)

## Architecture

| Type | Purpose |
|------|---------|
| `GuardrailMonitor` trait | Defines `check()` + `is_valid_at_any_stopping_point()` |
| `GuardrailVerdict` | Allow / Block / Warn with severity ordering |
| `SystemState` | Snapshot of system state for monitor evaluation |
| `BudgetId` | Identifies the budget a monitor protects |
| `GuardrailMonitorSet` | Runs all monitors, returns most restrictive verdict |

## Concrete Monitors

| Monitor | Budget | Blocks When |
|---------|--------|-------------|
| `MemoryBudgetGuardrail` | memory_budget | Usage exceeds configurable threshold (default 95%) |
| `DurabilityLossGuardrail` | durability_budget | Durability ratio below minimum (default 0.9) |
| `HardeningRegressionGuardrail` | hardening_regression | Proposed level < current level (INV-001) |
| `EvidenceEmissionGuardrail` | evidence_emission | Evidence disabled for policy action (INV-002) |

## Key Properties

- **Anytime-valid:** Monitor conclusions valid at any stopping point
- **Most restrictive:** `GuardrailMonitorSet.check_all()` returns Block > Warn > Allow
- **Envelope minimums:** Memory threshold >= 0.5; durability floor >= 0.5
- **Deterministic:** No randomness, no wall-clock dependency

## Event Codes

| Code | Trigger |
|------|---------|
| `EVD-GUARD-001` | Monitor check passed (Allow) |
| `EVD-GUARD-002` | Monitor block (includes budget_id, reason) |
| `EVD-GUARD-003` | Monitor warn |
| `EVD-GUARD-004` | Threshold reconfigured |

## Invariants

| ID | Status |
|----|--------|
| INV-GUARD-ANYTIME | Verified (optional stopping tests) |
| INV-GUARD-PRECEDENCE | Verified (Block overrides Warn/Allow) |
| INV-GUARD-RESTRICTIVE | Verified (most_restrictive verdict selection) |
| INV-GUARD-CONFIGURABLE | Verified (threshold enforcement with minimums) |

## Verification Results

| Check | Result |
|-------|--------|
| GuardrailMonitor trait exists | PASS |
| GuardrailVerdict with Allow/Block/Warn | PASS |
| SystemState with required fields | PASS |
| 4 concrete monitors implemented | PASS |
| GuardrailMonitorSet with check_all/evaluate | PASS |
| EVD-GUARD event codes (001-004) | PASS |
| Anytime-valid property tested | PASS |
| Threshold enforcement with envelope minimums | PASS |
| 91 Rust unit tests | PASS |
| Spec document exists | PASS |
| Telemetry CSV with 12 rows | PASS |
| Direct git_xref evidence | PASS |

### Test Summary

| Category | Count | Status |
|----------|-------|--------|
| Rust unit tests | 91 | All pass |
| Python verification checks | 12 | All pass |
| Python unit tests | 18 | All pass |

## Completion-Debt Closure

`bd-3a3q.1` is resolved by recording direct git xref evidence for the shipped implementation:

- `10f532f3bcb7d988f9d8e868cbdd384ba8828bad` added `crates/franken-node/src/policy/guardrail_monitor.rs`.
- `911db31bb1aa1cefdebbdae2f1e663fdb9f83fa7` hardened bounded finding growth in the same module.

## Downstream Unblocked

- bd-15u3: Guardrail precedence over Bayesian recommendations
- bd-1zym: Automatic hardening trigger on guardrail rejection
- bd-3epz: Section 10.14 verification gate
- bd-5rh: 10.14 plan gate
