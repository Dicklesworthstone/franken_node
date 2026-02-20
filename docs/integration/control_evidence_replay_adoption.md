# Control Evidence Replay Adoption

## Bead: bd-tyr2 | Section: 10.15

## Purpose

Integrates the canonical evidence-ledger replay validator (bd-2ona, Section 10.14) into
franken_node's control-plane decision gates so that every policy-influenced decision can
be verified post-hoc via deterministic replay.

## Decision Type Coverage

Each control-plane decision type (from bd-15j6) is mapped to a replay invocation:

| Decision Type | Decision Kinds | Replay Context Source |
|---------------|----------------|----------------------|
| HealthGateEval | Admit, Deny | health_score, threshold, pass/fail candidates |
| RolloutTransition | Admit, Deny | canary_pass_rate, phase, proceed/abort candidates |
| QuarantineAction | Quarantine, Release | trust_score, threshold, promote/demote candidates |
| FencingDecision | Admit, Deny | lease_valid, epoch_match, grant/deny candidates |
| MigrationDecision | Admit, Deny | schema_compatible, data_integrity, proceed/abort candidates |

## Replay Protocol

1. After a control decision is made and evidence is emitted (via `ControlEvidenceEmitter`),
   the replay integration captures the `ControlEvidenceEntry` and constructs a `ReplayContext`
   from the entry's `policy_inputs` and `candidates_considered` fields.

2. The `EvidenceReplayValidator` from `tools::evidence_replay_validator` is invoked with the
   evidence entry and context.

3. The verdict is one of:
   - **REPRODUCED** (`ReplayResult::Match`): The replayed decision matches the recorded one.
     Control-plane gate passes. Event code: `RPL-002`.
   - **DIVERGED** (`ReplayResult::Mismatch`): The replayed decision differs. A minimal
     deterministic diff is emitted. Control-plane gate fails. Event code: `RPL-003`.
   - **ERROR** (`ReplayResult::Unresolvable`): The validator could not complete replay
     (missing context, epoch mismatch). Control-plane gate fails. Event code: `RPL-004`.

## Gate Behavior

- `REPRODUCED` -> gate passes, decision proceeds normally.
- `DIVERGED` -> gate fails, diff artifact logged, release blocked.
- `ERROR` -> gate fails, error details logged, release blocked.

## Prohibition on Custom Replay Logic

The product layer MUST use the canonical 10.14 replay validator (`EvidenceReplayValidator`).
No custom replay logic may be introduced in the control-plane layer. This ensures a single
source of truth for deterministic verification.

## Event Codes

| Code | When Emitted |
|------|-------------|
| RPL-001 | Replay initiated for a control decision |
| RPL-002 | Replay verdict: REPRODUCED (match) |
| RPL-003 | Replay verdict: DIVERGED (mismatch with diff) |
| RPL-004 | Replay verdict: ERROR (unresolvable) |
| RPL-005 | Gate decision based on replay verdict |

## Invariants

| ID | Statement |
|----|-----------|
| INV-RPL-CANONICAL | Product layer uses only the canonical 10.14 replay validator |
| INV-RPL-DETERMINISTIC | Same evidence + inputs always produces the same verdict |
| INV-RPL-FAIL-CLOSED | DIVERGED or ERROR verdicts block the control-plane gate |
| INV-RPL-COMPLETE | All 5 decision types have replay coverage |

## Dependencies

- Upstream: bd-2ona (10.14 canonical replay validator), bd-15j6 (10.15 control evidence emission)
- Downstream: bd-20eg (section gate)
