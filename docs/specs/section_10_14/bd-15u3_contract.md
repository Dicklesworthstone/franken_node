# bd-15u3: Guardrail Precedence Enforcement

## Overview

The decision engine enforces a strict precedence rule: anytime-valid guardrail
bounds always override Bayesian posterior recommendations. This is the
integration point between the Bayesian diagnostics engine (bd-2igi) and the
guardrail monitor set (bd-3a3q).

## Precedence Rule

1. The Bayesian engine produces a ranked list of candidate actions sorted by
   posterior probability (highest first).
2. The decision engine iterates candidates in rank order.
3. For each candidate it checks:
   - **System-level guardrails** via `GuardrailMonitorSet.check_all_detailed(state)`.
     If any monitor returns `Block`, the candidate is blocked.
   - **Per-candidate guardrail filter** via `RankedCandidate.guardrail_filtered`.
     If `true`, the candidate is blocked.
4. The first candidate that passes all checks is chosen.
5. If no candidate passes, `DecisionOutcome::AllBlocked` is returned (never a
   panic).

## Types

| Type | Purpose |
|------|---------|
| `DecisionEngine` | Stateless engine parameterized by epoch_id |
| `DecisionOutcome` | Result: chosen candidate, blocked list, reason, epoch |
| `BlockedCandidate` | Blocked candidate with guardrail IDs, rank, reasons |
| `DecisionReason` | TopCandidateAccepted / TopCandidateBlockedFallbackUsed / AllCandidatesBlocked / NoCandidates |
| `GuardrailId` | Identifies the specific guardrail that blocked a candidate |

## Event Codes

| Code | Trigger |
|------|---------|
| EVD-DECIDE-001 | Decision made (top candidate accepted) |
| EVD-DECIDE-002 | Candidate blocked by guardrail |
| EVD-DECIDE-003 | All candidates blocked |
| EVD-DECIDE-004 | Fallback to lower-ranked candidate |

## Invariants

| ID | Description |
|----|-------------|
| INV-DECIDE-PRECEDENCE | Guardrail verdicts override Bayesian rankings |
| INV-DECIDE-DETERMINISTIC | Identical inputs produce identical outputs |
| INV-DECIDE-NO-PANIC | AllBlocked returned, never a panic |

## Fallback Behaviour

When the top-ranked candidate is blocked:
- The engine tries the next candidate in rank order.
- `DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank }` records
  which rank was ultimately chosen.
- If all candidates are blocked, `DecisionReason::AllCandidatesBlocked` is
  returned with a full `blocked` list for operator inspection.

## AllBlocked Handling

When every candidate is blocked:
- `chosen` is `None`.
- `blocked` contains every candidate with the specific guardrail(s) and reasons.
- The caller (policy controller) must decide how to proceed -- typically
  escalating to an operator.

## Dependencies

- **Upstream**: bd-2igi (Bayesian posterior diagnostics), bd-3a3q (guardrail monitors)
- **Downstream**: bd-mwvn (policy explainer), bd-3epz (section gate), bd-5rh (plan gate)
