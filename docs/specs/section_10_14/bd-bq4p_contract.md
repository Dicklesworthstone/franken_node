# bd-bq4p: Controller Boundary Checks Rejecting Correctness-Semantic Mutations

## Purpose

Enforce the correctness envelope (bd-sddz) at runtime by intercepting every
policy proposal before it can take effect and rejecting any proposal that would
mutate a correctness-semantic invariant. This is the enforcement layer that
makes the envelope's promises real.

## Dependencies

- **Upstream:** bd-sddz (correctness envelope — provides invariant definitions)
- **Downstream:** bd-3epz (section gate), bd-5rh (10.14 plan gate)

## Types

### `ErrorClass`

Stable error classification for boundary violations:
- `CorrectnessSemanticMutation` — proposal targets an immutable invariant field
- `EnvelopeBypass` — proposal attempts to bypass the checker entirely
- `UnknownInvariantTarget` — proposal targets an unrecognized invariant

### `BoundaryViolation`

Rejection details: `violated_invariant: InvariantId`, `proposal_summary: String`,
`rejection_reason: String`, `stable_error_class: ErrorClass`.

### `RejectedMutationRecord`

Audit record: `timestamp: u64`, `proposal_summary: String`,
`violated_invariant: InvariantId`, `controller_id: String`,
`error_class: ErrorClass`, `epoch_id: u64`.

### `ControllerBoundaryChecker`

Pre-apply checker with an in-memory audit trail of rejected mutations.

## Operations

### `check_proposal(proposal, envelope) -> Result<(), BoundaryViolation>`

Validates a policy proposal against the correctness envelope. Returns Ok(())
for valid proposals, Err(BoundaryViolation) for violations.

### `rejected_mutations() -> &[RejectedMutationRecord]`

Returns the audit trail of all rejected mutation attempts.

### `rejection_count() -> usize`

Returns count of rejected mutations.

### `rejection_report() -> serde_json::Value`

Generates a JSON rejection report with per-invariant counts and error class
distribution.

## Event Codes

| Code | Description |
|------|-------------|
| EVD-BOUNDARY-001 | Check passed — proposal is within envelope |
| EVD-BOUNDARY-002 | Rejection — proposal violates invariant |
| EVD-BOUNDARY-003 | Audit trail write — rejected mutation recorded |
| EVD-BOUNDARY-004 | Checker initialization |

## Invariants

| ID | Description |
|----|-------------|
| INV-BOUNDARY-MANDATORY | Every proposal must pass through check_proposal before apply |
| INV-BOUNDARY-AUDITABLE | Every rejection is recorded in the audit trail |
| INV-BOUNDARY-STABLE-ERRORS | ErrorClass variants are stable across versions |
| INV-BOUNDARY-FAIL-CLOSED | Unknown/malformed proposals are rejected, not passed |

## Artifacts

- Implementation: `crates/franken-node/src/policy/controller_boundary_checks.rs`
- Spec: `docs/specs/section_10_14/bd-bq4p_contract.md`
- Evidence: `artifacts/section_10_14/bd-bq4p/verification_evidence.json`
- Summary: `artifacts/section_10_14/bd-bq4p/verification_summary.md`
