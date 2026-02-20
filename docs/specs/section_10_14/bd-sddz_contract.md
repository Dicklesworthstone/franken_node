# bd-sddz: Immutable Correctness Envelope

## Decision Statement

Define and implement the correctness envelope: a formal boundary between "tunable policy" and "immutable correctness" that no policy controller is permitted to modify.

## Dependencies

- **Upstream**: bd-nupr (EvidenceEntry schema) — evidence emission invariant references the entry type.
- **Downstream**: bd-bq4p (controller boundary checks), bd-3a3q (guardrail monitors), bd-2ona (replay validator), bd-3epz (section gate), bd-5rh (10.14 plan gate).

## Terminology

| Term | Definition |
|------|-----------|
| Correctness Envelope | The set of invariants that are structurally immutable; no controller can modify them. |
| Tunable Policy | Parameters that controllers are permitted to adjust (budgets, thresholds, scheduling). |
| Invariant | A correctness property that must hold at all times; violation is a system error. |
| Policy Proposal | A structured request from a controller to change one or more policy fields. |
| Enforcement Mode | How an invariant is enforced: Compile (type system), Runtime (gates), Conformance (tests). |

## Invariants

The correctness envelope defines 12 immutable invariants:

| ID | Name | Owner | Enforcement |
|----|------|-------|-------------|
| INV-001-MONOTONIC-HARDENING | Monotonic hardening direction | 10.14 | Runtime |
| INV-002-EVIDENCE-EMISSION | Evidence emission mandatory | 10.14 | Runtime |
| INV-003-DETERMINISTIC-SEED | Deterministic seed derivation algorithm | 10.14 | Compile |
| INV-004-INTEGRITY-PROOF-VERIFICATION | Integrity proof verification cannot be bypassed | 10.14 | Runtime |
| INV-005-RING-BUFFER-FIFO | Ring buffer overflow policy is FIFO | 10.14 | Compile |
| INV-006-EPOCH-MONOTONIC | Epoch boundaries are monotonically increasing | 10.14 | Runtime |
| INV-007-WITNESS-HASH-SHA256 | Witness reference integrity hashes are SHA-256 | 10.14 | Compile |
| INV-008-GUARDRAIL-PRECEDENCE | Guardrail precedence over Bayesian recommendations | 10.14 | Runtime |
| INV-009-OBJECT-CLASS-APPEND-ONLY | Object class profiles are versioned and append-only | 10.14 | Runtime |
| INV-010-REMOTE-CAP-REQUIRED | Remote capability tokens required for network operations | 10.14 | Runtime |
| INV-011-MARKER-CHAIN-APPEND-ONLY | Marker stream is append-only | 10.14 | Runtime |
| INV-012-RECEIPT-CHAIN-IMMUTABLE | Decision receipt chain is immutable | 10.5 | Runtime |

## Error Codes

| Code | Condition |
|------|-----------|
| EVD-ENVELOPE-001 | Envelope check passed (proposal is within tunable policy). |
| EVD-ENVELOPE-002 | Envelope violation detected (proposal targets an immutable invariant). |
| EVD-ENVELOPE-003 | Envelope loaded at startup. |

## Rationale

The correctness envelope draws a hard line between what controllers can tune and what is structurally fixed. This is directly inspired by FrankenSQLite's immutable page-header invariants (9J enhancement map) and enforces Section 8.5 Invariant #1: correctness guarantees are never policy-overridable.

## Artifacts

| Artifact | Location |
|----------|----------|
| Implementation | `crates/franken-node/src/policy/correctness_envelope.rs` |
| Module root | `crates/franken-node/src/policy/mod.rs` |
| Governance spec | `docs/specs/section_10_14/bd-sddz_contract.md` (this file) |
| Manifest | `artifacts/10.14/correctness_envelope_manifest.json` |
| Verification evidence | `artifacts/section_10_14/bd-sddz/verification_evidence.json` |
| Verification summary | `artifacts/section_10_14/bd-sddz/verification_summary.md` |
| Verification script | `scripts/check_correctness_envelope.py` |
| Script tests | `tests/test_check_correctness_envelope.py` |
