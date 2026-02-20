# bd-3rya: Monotonic Hardening State Machine with One-Way Escalation

## Purpose

Enforce that the system's integrity assurance level can only increase over time.
Downward transitions require an explicit governance rollback artifact that creates
an auditable exception. Directly supports Section 8.5 Invariant #4 (monotonic
safety progression).

## Dependencies

- **Upstream:** none (foundational component for the hardening subsystem)

## Types

### `HardeningLevel`

Five totally-ordered levels: `Baseline < Standard < Enhanced < Maximum < Critical`.
Implements `Copy + Ord + Hash + Eq` for ergonomic comparisons.

### `HardeningStateMachine`

State machine tracking the current level with a transition log.

### `GovernanceRollbackArtifact`

Required for downward transitions: `artifact_id`, `approver_id`, `reason`,
`timestamp`, `signature`. All fields must be non-empty.

### `TransitionRecord`

Audit record: `from_level`, `to_level`, `timestamp`, `trigger`, `trace_id`.

### `HardeningError`

Four error codes:
- `HARDEN_ILLEGAL_REGRESSION` — escalation to same or lower level
- `HARDEN_INVALID_ARTIFACT` — invalid governance rollback artifact
- `HARDEN_INVALID_ROLLBACK_TARGET` — rollback to same or higher level
- `HARDEN_AT_MAXIMUM` — already at Critical level

## Operations

### `escalate(target, timestamp, trace_id) -> Result<TransitionRecord>`

INV-HARDEN-MONOTONIC: only accepts strictly higher target level.

### `governance_rollback(target, artifact, timestamp, trace_id) -> Result<TransitionRecord>`

INV-HARDEN-GOVERNANCE: requires valid signed artifact; target must be strictly lower.

### `replay_transitions(log) -> HardeningStateMachine`

INV-HARDEN-DURABLE: reconstructs state identically from the transition log.

## Invariants

| ID | Description |
|----|-------------|
| INV-HARDEN-MONOTONIC | Level only increases without governance rollback |
| INV-HARDEN-DURABLE | State can be replayed from transition log |
| INV-HARDEN-AUDITABLE | Every transition is recorded with timestamp/trigger |
| INV-HARDEN-GOVERNANCE | Rollback requires valid signed governance artifact |

## Artifacts

- Implementation: `crates/franken-node/src/policy/hardening_state_machine.rs`
- Spec: `docs/specs/section_10_14/bd-3rya_contract.md`
- Evidence: `artifacts/section_10_14/bd-3rya/verification_evidence.json`
- Summary: `artifacts/section_10_14/bd-3rya/verification_summary.md`
