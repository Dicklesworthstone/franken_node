# bd-sh3: Policy Change Approval Workflows with Cryptographic Audit Trail

## Bead: bd-sh3 | Section: 10.5

## Purpose

Implements the governance chokepoint for policy mutations: every policy change must
be cryptographically signed, multi-party approved, and recorded in a tamper-evident
append-only hash-chained ledger. Enforces key-role separation so the proposer cannot
be the sole approver.

## Invariants

| ID | Statement |
|----|-----------|
| INV-POL-MULTI-PARTY | Policy changes require M-of-N cryptographic signatures from distinct role holders. |
| INV-POL-ROLE-SEP | The proposer cannot be the sole approver; at least one other distinct identity must approve. |
| INV-POL-HASH-CHAIN | Audit ledger is append-only with SHA-256 hash-chained entries; tampering is detected on read. |
| INV-POL-ROLLBACK | Every activated change has a deterministic rollback command; rollback follows the same approval workflow. |
| INV-POL-EVIDENCE | Activation emits a structured evidence package with full diff, signatures, and approval chain. |
| INV-POL-JUSTIFICATION | Proposal justification must be at least 20 characters. |
| INV-POL-ENVELOPE | Changes touching correctness-envelope parameters are flagged for elevated governance. |
| INV-POL-LIFECYCLE | Full state machine: Proposed -> UnderReview -> Approved/Rejected -> Applied -> RolledBack. |

## Approval Protocol State Machine

```
Proposed -> UnderReview -> Approved -> Applied -> RolledBack
                       |-> Rejected
```

## Event Codes

| Code | When Emitted |
|------|--------------|
| POLICY_CHANGE_PROPOSED | New proposal submitted. |
| POLICY_CHANGE_REVIEWED | Approval signature added (quorum not yet met). |
| POLICY_CHANGE_APPROVED | Quorum met, proposal approved. |
| POLICY_CHANGE_REJECTED | Proposal rejected. |
| POLICY_CHANGE_ACTIVATED | Approved change activated (policy applied). |
| POLICY_CHANGE_ROLLED_BACK | Applied change rolled back. |
| AUDIT_CHAIN_VERIFIED | Hash chain integrity verified. |
| AUDIT_CHAIN_BROKEN | Hash chain integrity violation detected. |

## Error Codes

| Code | Condition |
|------|-----------|
| ERR_PROPOSAL_NOT_FOUND | Referenced proposal ID does not exist. |
| ERR_SOLE_APPROVER | Proposer attempted to be the sole approver. |
| ERR_INVALID_SIGNATURE | Signature verification failed. |
| ERR_QUORUM_NOT_MET | Insufficient approvals for activation. |
| ERR_INVALID_STATE_TRANSITION | Operation not valid in current state. |
| ERR_AUDIT_CHAIN_BROKEN | Hash chain integrity violation. |
| ERR_JUSTIFICATION_TOO_SHORT | Justification under 20 characters. |

## Dependencies

- Upstream: bd-3nr (degraded-mode policy), Section 10.10 (key-role separation), Section 10.14 (correctness envelope)
- Downstream: bd-1koz (section gate), bd-20a (section rollup)
