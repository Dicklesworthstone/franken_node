# bd-sddz: Immutable Correctness Envelope — Verification Summary

## Bead

| Field | Value |
|-------|-------|
| ID | bd-sddz |
| Title | Define immutable correctness envelope that policy controllers are forbidden to modify |
| Section | 10.14 |
| Status | Closed |
| Implemented by | CrimsonCrane |

## What Was Built

The correctness envelope defines a hard boundary between "tunable policy" (budgets, thresholds, scheduling) and "immutable correctness" (invariants no controller can override). This implements Section 8.5 Invariant #1: correctness guarantees are never policy-overridable.

### Implementation

- **`crates/franken-node/src/policy/correctness_envelope.rs`** — 12 immutable invariants, `is_within_envelope()` rejection gate, manifest export, full test suite (33 Rust unit tests).
- **`crates/franken-node/src/policy/mod.rs`** — module wiring.

### Invariants Defined (12)

| ID | Name | Enforcement |
|----|------|-------------|
| INV-001 | Monotonic hardening direction | Runtime |
| INV-002 | Evidence emission mandatory | Runtime |
| INV-003 | Deterministic seed derivation algorithm | Compile |
| INV-004 | Integrity proof verification cannot be bypassed | Runtime |
| INV-005 | Ring buffer overflow policy is FIFO | Compile |
| INV-006 | Epoch boundaries are monotonically increasing | Runtime |
| INV-007 | Witness reference integrity hashes are SHA-256 | Compile |
| INV-008 | Guardrail precedence over Bayesian recommendations | Runtime |
| INV-009 | Object class profiles are versioned and append-only | Runtime |
| INV-010 | Remote capability tokens required for network operations | Runtime |
| INV-011 | Marker stream is append-only | Runtime |
| INV-012 | Decision receipt chain is immutable | Runtime |

### Immutable Fields

25 policy field prefixes mapped to their governing invariant. Any `PolicyProposal` targeting these fields is rejected with an `EnvelopeViolation`.

## Verification Results

| Check | Result |
|-------|--------|
| Implementation exists with CorrectnessEnvelope struct | PASS |
| Module wired into policy/mod.rs | PASS |
| At least 10 invariants defined (actual: 12) | PASS |
| All invariant IDs unique | PASS |
| No EnforcementMode::None | PASS |
| is_within_envelope function present | PASS |
| EVD-ENVELOPE log codes (001, 002, 003) present | PASS |
| Governance spec exists with invariant references | PASS |
| Manifest artifact valid with 12 invariants | PASS |
| Test coverage for all invariant rejection paths | PASS |

### Test Summary

| Category | Count | Status |
|----------|-------|--------|
| Rust unit tests (correctness_envelope) | 33 | All pass |
| Python verification checks | 10 | All pass |
| Python unit tests (test_check_correctness_envelope) | 6 | All pass |

## Artifacts

| Artifact | Path |
|----------|------|
| Implementation | `crates/franken-node/src/policy/correctness_envelope.rs` |
| Module root | `crates/franken-node/src/policy/mod.rs` |
| Governance spec | `docs/specs/section_10_14/bd-sddz_contract.md` |
| Manifest | `artifacts/10.14/correctness_envelope_manifest.json` |
| Evidence | `artifacts/section_10_14/bd-sddz/verification_evidence.json` |
| Verification script | `scripts/check_correctness_envelope.py` |
| Script tests | `tests/test_check_correctness_envelope.py` |

## Downstream Unblocked

- bd-bq4p: Controller boundary checks rejecting correctness-semantic mutations
- bd-3a3q: Anytime-valid guardrail monitor set
- bd-2ona: Evidence-ledger replay validator
- bd-2igi: Bayesian posterior diagnostics
- bd-3epz: Section 10.14 verification gate
- bd-5rh: 10.14 plan gate
