# bd-1ayu: Verification Summary

## Overhead/Rate Clamp Policy for Hardening Escalations

**Section:** 10.14 (FrankenSQLite Deep-Mined Expansion)
**Status:** PASS (13/13 checks)
**Agent:** CrimsonCrane (claude-code, claude-opus-4-6)
**Date:** 2026-02-20

## Implementation

- **Module:** `crates/franken-node/src/policy/hardening_clamps.rs`
- **Spec:** `docs/specs/section_10_14/bd-1ayu_contract.md`
- **Verification:** `scripts/check_hardening_clamps.py`
- **Test Suite:** `tests/test_check_hardening_clamps.py` (19 tests)

## Data Model

| Type | Purpose |
|------|---------|
| `EscalationBudget` | Rate/overhead limits, min/max level bounds |
| `ClampResult` | Allowed / Clamped / Denied with reasons |
| `ClampEvent` | Telemetry event with CSV serialization |
| `HardeningClampPolicy` | Policy engine with history tracking |

## Key Behaviors

- **Rate limiting:** Counts escalations within a rolling window; blocks when `count >= max_escalations_per_window`
- **Overhead limiting:** Fixed overhead % per level; clamps to highest level within budget
- **Min/max bounds:** Policy floor and ceiling enforced before other checks
- **Determinism:** No randomness, no wall-clock dependency; identical inputs produce identical outputs (verified across 1000 runs)
- **Zero-budget edge cases:** `max_escalations_per_window = 0` blocks all; `max_overhead_pct = 0.0` blocks all above Baseline; `window_duration_ms = 0` treats all history as outside window

## Overhead Model

| Level | Overhead % |
|-------|-----------|
| Baseline | 0.0 |
| Standard | 5.0 |
| Enhanced | 15.0 |
| Maximum | 35.0 |
| Critical | 60.0 |

## Event Codes

| Code | Trigger |
|------|---------|
| `EVD-CLAMP-001` | Escalation allowed |
| `EVD-CLAMP-002` | Escalation clamped |
| `EVD-CLAMP-003` | Escalation denied |
| `EVD-CLAMP-004` | Budget recalculated |

## Verification Results

| Check | Result |
|-------|--------|
| HardeningClampPolicy struct exists | PASS |
| EscalationBudget with required fields | PASS |
| ClampResult with Allowed/Clamped/Denied | PASS |
| check_escalation function present | PASS |
| ClampEvent with fields and CSV support | PASS |
| EVD-CLAMP event codes (001-004) | PASS |
| Rate limit logic with window counting | PASS |
| Overhead limit logic with fallback | PASS |
| Determinism test (1000 runs) | PASS |
| Min/max level bound enforcement | PASS |
| 32 unit tests (>= 25 required) | PASS |
| Spec document with required content | PASS |
| Metrics CSV with 11 data rows | PASS |

### Test Summary

| Category | Count | Status |
|----------|-------|--------|
| Rust unit tests | 32 | All pass |
| Python verification checks | 13 | All pass |
| Python unit tests | 19 | All pass |

## Artifacts

| Artifact | Path |
|----------|------|
| Implementation | `crates/franken-node/src/policy/hardening_clamps.rs` |
| Spec | `docs/specs/section_10_14/bd-1ayu_contract.md` |
| Metrics CSV | `artifacts/10.14/hardening_clamp_metrics.csv` |
| Evidence | `artifacts/section_10_14/bd-1ayu/verification_evidence.json` |
| Verification script | `scripts/check_hardening_clamps.py` |
| Script tests | `tests/test_check_hardening_clamps.py` |

## Downstream Unblocked

- bd-1fp4: Integrity sweep escalation/de-escalation policy
- bd-3epz: Section 10.14 verification gate
- bd-5rh: 10.14 plan gate
