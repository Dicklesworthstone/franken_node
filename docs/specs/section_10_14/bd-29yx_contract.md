# bd-29yx: Suspicious-Artifact Challenge Flow

## Overview

When an artifact is flagged as suspicious, trust promotion is deferred pending
a challenge flow. The system issues a challenge requesting specific proof
artifacts. Promotion proceeds only after proof verification succeeds.
Unresolved challenges timeout to denial.

## Module

`crates/franken-node/src/security/challenge_flow.rs`

## State Machine

```
Pending -> ChallengeIssued -> ProofReceived -> ProofVerified -> Promoted
     \            \                \                \
      -> Denied    -> Denied        -> Denied        -> Denied
```

Terminal states: Denied, Promoted (no further transitions).

## Types

| Type | Purpose |
|------|---------|
| `ChallengeId` | Unique challenge identifier |
| `ArtifactId` | Artifact under challenge |
| `SuspicionReason` | Why the artifact was flagged |
| `RequiredProofType` | What proof is needed |
| `ChallengeState` | State machine states |
| `ProofSubmission` | Submitted proof artifact |
| `ChallengeConfig` | Timeout and policy config |
| `ChallengeAuditEntry` | Hash-chained audit log entry |
| `ChallengeError` | Structured error |
| `ChallengeMetrics` | Flow counters |
| `Challenge` | Full challenge record |
| `ChallengeFlowController` | Controller managing flows |

## Event Codes

| Code | Trigger |
|------|---------|
| CHALLENGE_ISSUED | Challenge created for suspicious artifact |
| CHALLENGE_PROOF_RECEIVED | Proof artifact submitted |
| CHALLENGE_VERIFIED | Proof passed verification |
| CHALLENGE_TIMED_OUT | Challenge expired, auto-denied |
| CHALLENGE_DENIED | Artifact denied promotion |
| CHALLENGE_PROMOTED | Artifact promoted after verification |

## Invariants

| ID | Rule |
|----|------|
| INV-CHALLENGE-DEFER | Suspicious artifacts never promoted without proof |
| INV-CHALLENGE-TIMEOUT-DENY | Unresolved challenges default to denial |
| INV-CHALLENGE-AUDIT | All state transitions logged with hash chain |
| INV-CHALLENGE-VALID-TRANSITIONS | Invalid transitions rejected |

## Acceptance Criteria

1. State machine enforces valid transitions; invalid ones return error.
2. Duplicate active challenges on same artifact rejected.
3. Timeout auto-denies unresolved challenges (configurable).
4. Audit log is hash-chained for tamper evidence.
5. Metrics track issued/resolved/timed-out/promoted/denied totals.
6. Full happy path: issue -> submit proof -> verify -> promote.
7. Denial possible from any non-terminal state.
