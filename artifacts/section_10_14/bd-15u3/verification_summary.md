# bd-15u3: Verification Summary

## Guardrail Precedence over Bayesian Recommendations

**Section:** 10.14 (FrankenSQLite Deep-Mined Expansion)
**Status:** PASS (61/61 checks)
**Agent:** CrimsonCrane (claude-code, claude-opus-4-6)
**Date:** 2026-02-20

## Implementation

- **Module:** `crates/franken-node/src/policy/decision_engine.rs`
- **Spec:** `docs/specs/section_10_14/bd-15u3_contract.md`
- **Verification:** `scripts/check_decision_engine.py`
- **Test Suite:** `tests/test_check_decision_engine.py` (25 tests)

## Architecture

| Type | Purpose |
|------|---------|
| `DecisionEngine` | Applies guardrail checks to Bayesian rankings |
| `DecisionOutcome` | Result with chosen candidate, blocked list, reason, epoch |
| `BlockedCandidate` | Blocked candidate with guardrail IDs and reasons |
| `DecisionReason` | TopCandidateAccepted, TopCandidateBlockedFallbackUsed, AllCandidatesBlocked, NoCandidates |
| `GuardrailId` | Identifier for a specific blocking guardrail |

## Precedence Rule

1. Candidates arrive in Bayesian rank order (highest posterior first)
2. System-level guardrails block all candidates if system invariants violated
3. Per-candidate `guardrail_filtered` flag blocks individual candidates
4. First passing candidate is chosen; `AllCandidatesBlocked` if none pass

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
| INV-DECIDE-PRECEDENCE | Verified (guardrails always override Bayesian rankings) |
| INV-DECIDE-DETERMINISTIC | Verified (identical inputs produce identical outcomes) |
| INV-DECIDE-NO-PANIC | Verified (AllBlocked returned, never panics) |

## Test Summary

| Category | Count | Status |
|----------|-------|--------|
| Rust unit tests | 34 | All pass |
| Python verification checks | 61 | All pass |
| Python unit tests | 25 | All pass |

## Downstream Unblocked

- bd-mwvn: Policy action explainer (depends on precedence decisions)
- bd-3epz: Section 10.14 verification gate
- bd-5rh: 10.14 plan gate
