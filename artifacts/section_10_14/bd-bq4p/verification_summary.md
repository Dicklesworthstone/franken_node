# bd-bq4p: Controller Boundary Checks — Verification Summary

## Bead

| Field | Value |
|-------|-------|
| ID | bd-bq4p |
| Title | Implement controller boundary checks rejecting any attempted correctness-semantic mutation |
| Section | 10.14 |
| Status | Closed |

## What Was Built

Pre-apply enforcement layer that intercepts every policy proposal and rejects any change targeting a correctness-semantic invariant from the correctness envelope (bd-sddz). Implements Section 8.5 Invariant #1: single, auditable enforcement point.

### Implementation

- **`crates/franken-node/src/policy/controller_boundary_checks.rs`** — `ControllerBoundaryChecker` with `check_proposal()`, audit trail, rejection report, serialize/restore. 38 Rust unit tests.

### Key Types

| Type | Purpose |
|------|---------|
| `ErrorClass` | Stable error enum: CorrectnessSemanticMutation, EnvelopeBypass, UnknownInvariantTarget |
| `BoundaryViolation` | Rejection details with invariant, summary, reason, error class |
| `RejectedMutationRecord` | Audit record: timestamp, proposal, invariant, controller, class, epoch |
| `ControllerBoundaryChecker` | Pre-apply checker with audit trail and counters |

### Event Codes

| Code | Description |
|------|-------------|
| EVD-BOUNDARY-001 | Check passed |
| EVD-BOUNDARY-002 | Rejection |
| EVD-BOUNDARY-003 | Audit trail write |
| EVD-BOUNDARY-004 | Checker initialization |

## Verification Results

| Check | Result |
|-------|--------|
| Implementation with required types | PASS |
| ErrorClass: 3 stable variants | PASS |
| BoundaryViolation: all fields | PASS |
| RejectedMutationRecord: all fields | PASS |
| All methods present | PASS |
| EVD-BOUNDARY-001 through 004 | PASS |
| INV-BOUNDARY-* markers | PASS |
| Upstream dep on bd-sddz | PASS |
| Fail-closed behavior | PASS |
| All 12 invariants rejected | PASS |
| Serde derives on types | PASS |
| Module registered | PASS |

### Test Summary

| Category | Count | Status |
|----------|-------|--------|
| Rust unit tests | 38 | All pass |
| Python verification checks | 73 | All pass |
| Python unit tests | 26 | All pass |

## Artifacts

| Artifact | Path |
|----------|------|
| Implementation | `crates/franken-node/src/policy/controller_boundary_checks.rs` |
| Spec contract | `docs/specs/section_10_14/bd-bq4p_contract.md` |
| Evidence | `artifacts/section_10_14/bd-bq4p/verification_evidence.json` |
| Verification script | `scripts/check_controller_boundary.py` |
| Script tests | `tests/test_check_controller_boundary.py` |
| Rejection report | `artifacts/10.14/controller_boundary_rejections.json` |

## Downstream Unblocked

- bd-3epz: Section 10.14 verification gate
- bd-5rh: 10.14 plan gate
