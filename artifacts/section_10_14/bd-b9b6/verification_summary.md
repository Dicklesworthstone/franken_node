# bd-b9b6: Verification Summary

## Durability Contract Violation Diagnostic Bundles

**Section:** 10.14 (FrankenSQLite Deep-Mined Expansion)
**Status:** PASS (71/71 checks)
**Agent:** CrimsonCrane (claude-code, claude-opus-4-6)
**Date:** 2026-02-20

## Implementation

- **Module:** `crates/franken-node/src/observability/durability_violation.rs`
- **Spec:** `docs/specs/section_10_14/bd-b9b6_contract.md`
- **Verification:** `scripts/check_durability_violation.py`
- **Test Suite:** `tests/test_check_durability_violation.py` (24 tests)

## Architecture

| Type | Purpose |
|------|---------|
| `BundleId` | Deterministically-derived unique bundle identifier |
| `CausalEvent` | Event in the causal chain leading to violation |
| `CausalEventType` | 5 variants: GuardrailRejection, HardeningEscalation, RepairFailed, IntegrityCheckFailed, ArtifactUnverifiable |
| `FailedArtifact` | Artifact with expected/actual hash and failure reason |
| `ProofContext` | Failed, missing, and passed proofs at violation time |
| `HaltPolicy` | HaltAll, HaltScope(scope), WarnOnly |
| `ViolationBundle` | Complete diagnostic bundle with full causal chain |
| `ViolationContext` | Input context for deterministic bundle generation |
| `DurabilityViolationDetector` | Manages halt state and generates bundles |
| `DurabilityHaltedError` | Error when durable op blocked by violation halt |

## Event Codes

| Code | Trigger |
|------|---------|
| EVD-VIOLATION-001 | Violation bundle generated |
| EVD-VIOLATION-002 | Gating operations halted |
| EVD-VIOLATION-003 | Halt cleared after remediation |
| EVD-VIOLATION-004 | Durable operation rejected during halt |

## Invariants

| ID | Status |
|----|--------|
| INV-VIOLATION-DETERMINISTIC | Verified (identical context -> identical bundle, 100-run test) |
| INV-VIOLATION-CAUSAL | Verified (complete ordered causal chain in every bundle) |
| INV-VIOLATION-HALT | Verified (gating halted per policy after emission) |

## Test Summary

| Category | Count | Status |
|----------|-------|--------|
| Rust unit tests | 30 | All pass |
| Python verification checks | 71 | All pass |
| Python unit tests | 24 | All pass |

## Downstream Unblocked

- bd-3epz: Section 10.14 verification gate
- bd-5rh: 10.14 plan gate
