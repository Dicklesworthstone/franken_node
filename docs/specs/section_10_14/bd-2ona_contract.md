# bd-2ona: Evidence-Ledger Replay Validator

**Section**: 10.14
**Depends on**: bd-2e73 (evidence ledger), bd-oolt (mandatory emission), bd-sddz (correctness envelope)

## Purpose

Offline validator that takes a captured `EvidenceEntry` with its decision context
(candidates, constraints, policy snapshot) and re-executes the decision logic to
confirm the recorded outcome matches. Closes the loop from "we recorded decisions"
to "we can prove decisions were deterministic."

## Key Types

| Type | Role |
|------|------|
| `EvidenceReplayValidator` | Stateful validator tracking results |
| `ReplayContext` | Frozen state at decision time: candidates, constraints, epoch |
| `ReplayResult` | Enum: Match, Mismatch (with diff), Unresolvable |
| `ReplayDiff` | Minimal human-readable diff of diverged fields |
| `ActionRef` | Reference to a specific action for comparison |
| `Candidate` | A candidate action with score and metadata |
| `Constraint` | An active constraint (satisfied or not) |
| `ReplaySummary` | Aggregate results: totals, matches, mismatches |

## Invariants

- **INV-REPLAY-DETERMINISTIC**: identical inputs always produce identical results
- **INV-REPLAY-COMPLETE**: all DecisionKind variants have replay coverage
- **INV-REPLAY-INDEPENDENT**: no wall-clock or random state dependency

## Event Codes

| Code | Meaning |
|------|---------|
| EVD-REPLAY-001 | Replay start |
| EVD-REPLAY-002 | Replay match |
| EVD-REPLAY-003 | Replay mismatch (with diff summary) |
| EVD-REPLAY-004 | Unresolvable context |

## Decision Replay Logic

The deterministic decision function selects the highest-scoring candidate whose
constraints are all satisfied. For Deny/Rollback decisions, no winning candidate
is expected (constraints blocked all candidates).

## Validation Modes

- **Single entry**: `validate(entry, context) -> ReplayResult`
- **Batch**: `validate_batch(entries) -> Vec<ReplayResult>`
- **Summary**: `summary_report() -> ReplaySummary`
