# bd-oolt: Mandatory Evidence Emission for Policy-Driven Actions

**Section**: 10.14
**Depends on**: bd-2e73 (evidence ledger ring buffer)

## Purpose

Every policy-driven control action (commit, abort, quarantine, release) must emit
an `EvidenceEntry` into the evidence ledger before execution proceeds. Missing
evidence constitutes a conformance violation that blocks the operation.

## Key Types

| Type | Role |
|------|------|
| `PolicyAction` | Enum: Commit, Abort, Quarantine, Release |
| `ActionId` | Stable action identifier for cross-referencing |
| `EvidenceRequirement` | Specifies what evidence each action must produce |
| `PolicyActionOutcome` | Result: Executed (with evidence) or Rejected (missing evidence) |
| `EvidenceConformanceChecker` | Middleware that verifies evidence before action execution |

## Invariants

- **INV-EVIDENCE-MANDATORY**: every policy action requires an evidence entry
- **INV-EVIDENCE-LINKAGE**: evidence entry links to action via action_id
- **INV-EVIDENCE-COMPLETE**: all DecisionKind variants are covered

## Event Codes

| Code | Meaning |
|------|---------|
| EVD-POLICY-001 | Successful evidence-linked action |
| EVD-POLICY-002 | Missing evidence rejection |
| EVD-POLICY-003 | Evidence/action linkage mismatch |

## Action Types

All four policy-driven control actions require evidence emission:

1. **Commit**: Data durability commitment (DecisionKind::Admit)
2. **Abort**: Operation cancellation (DecisionKind::Deny)
3. **Quarantine**: Suspicious artifact isolation (DecisionKind::Quarantine)
4. **Release**: Quarantine release / trust promotion (DecisionKind::Release)

## Conformance Contract

1. Caller produces an `EvidenceEntry` with matching `action_id`
2. `EvidenceConformanceChecker::verify_and_execute()` validates:
   - Evidence entry exists and is well-formed
   - `action_id` matches between evidence and action
   - `decision_kind` matches the action type
3. On validation pass: action executes, evidence is appended to ledger
4. On validation fail: action is rejected with stable error code
