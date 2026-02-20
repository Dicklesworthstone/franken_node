# bd-15u3: Verification Summary

## Guardrail Precedence Enforcement (Decision Engine)

**Section:** 10.14 (FrankenSQLite Deep-Mined Expansion)
**Status:** PASS (57/57 checks)
**Agent:** CrimsonCrane (claude-code, claude-opus-4-6)
**Date:** 2026-02-20

## Implementation

- **Module:** `crates/franken-node/src/policy/decision_engine.rs`
- **Spec:** `docs/specs/section_10_14/bd-15u3_contract.md`
- **Verification:** `scripts/check_decision_engine.py`
- **Test Suite:** `tests/test_check_decision_engine.py` (24 tests)

## Architecture

| Type | Purpose |
|------|---------|
| `DecisionEngine` | Stateless engine that enforces guardrail precedence |
| `DecisionOutcome` | Result with chosen candidate, blocked list, reason |
| `BlockedCandidate` | Blocked candidate with guardrail IDs and reasons |
| `DecisionReason` | TopCandidateAccepted / Fallback / AllBlocked / NoCandidates |
| `GuardrailId` | Identifies the specific guardrail that blocked a candidate |

## Key Properties

- **Guardrail precedence**: Guardrails always override Bayesian rankings (INV-DECIDE-PRECEDENCE)
- **Deterministic**: Identical inputs produce identical outputs (INV-DECIDE-DETERMINISTIC)
- **No-panic**: AllBlocked returned, never a panic (INV-DECIDE-NO-PANIC)
- **Dual-level checking**: System-level guardrails + per-candidate filters
- **Fallback**: Automatically falls through to next-best candidate when top is blocked

## Event Codes

| Code | Trigger |
|------|---------|
| EVD-DECIDE-001 | Decision made (top candidate accepted) |
| EVD-DECIDE-002 | Candidate blocked by guardrail |
| EVD-DECIDE-003 | All candidates blocked |
| EVD-DECIDE-004 | Fallback to lower-ranked candidate |

## Invariants

| ID | Status |
|----|--------|
| INV-DECIDE-PRECEDENCE | Verified (34 Rust tests cover all precedence scenarios) |
| INV-DECIDE-DETERMINISTIC | Verified (explicit determinism test) |
| INV-DECIDE-NO-PANIC | Verified (AllBlocked, NoCandidates, large sets all handled) |

## Test Summary

| Category | Count | Status |
|----------|-------|--------|
| Rust unit tests | 34 | All pass |
| Python verification checks | 57 | All pass |
| Python unit tests | 24 | All pass |

## Downstream Unblocked

- bd-mwvn: Policy action explainer
- bd-3epz: Section 10.14 verification gate
- bd-5rh: 10.14 plan gate
