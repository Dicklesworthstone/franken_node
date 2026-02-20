# bd-1daz: Verification Summary

## Retroactive Hardening Pipeline (Union-Only Protection Artifacts)

**Section:** 10.14 (FrankenSQLite Deep-Mined Expansion)
**Status:** PASS (83/83 checks)
**Agent:** CrimsonCrane (claude-code, claude-opus-4-6)
**Date:** 2026-02-20

## Implementation

- **Module:** `crates/franken-node/src/policy/retroactive_hardening.rs`
- **Spec:** `docs/specs/section_10_14/bd-1daz_contract.md`
- **Verification:** `scripts/check_retroactive_hardening.py`
- **Test Suite:** `tests/test_check_retroactive_hardening.py` (25 tests)

## Architecture

| Type | Purpose |
|------|---------|
| `RetroactiveHardeningPipeline` | Generates protection artifacts for level gap |
| `CanonicalObject` | Object with stable identity (object_id, content_hash) |
| `ObjectId` | Unique identifier for canonical objects |
| `ProtectionType` | Enum: Checksum, Parity, IntegrityProof, RedundantCopy |
| `ProtectionArtifact` | Protection data appended alongside canonical objects |
| `RepairabilityScore` | Fraction (0.0-1.0) recoverable from artifacts |
| `HardeningProgressRecord` | Per-object progress for evidence ledger |
| `HardeningResult` | Corpus-wide hardening result |

## Key Properties

- **Union-only**: Protection artifacts stored alongside, never inside canonical objects
- **Identity stable**: `verify_identity_stable()` confirms object unchanged
- **Monotonic repairability**: Score only increases after hardening
- **Idempotent**: Re-hardening at same level produces no new artifacts
- **Deterministic**: Artifact data is reproducible from same inputs

## Protection Types per Level

| Level | Types | Repairability |
|-------|-------|---------------|
| Baseline | (none) | 0.00 |
| Standard | Checksum | 0.10 |
| Enhanced | Checksum, Parity | 0.30 |
| Maximum | Checksum, Parity, IntegrityProof | 0.45 |
| Critical | Checksum, Parity, IntegrityProof, RedundantCopy | 0.95 |

## Event Codes

| Code | Trigger |
|------|---------|
| EVD-RETROHARDEN-001 | Pipeline started |
| EVD-RETROHARDEN-002 | Object hardened |
| EVD-RETROHARDEN-003 | Identity verification passed |
| EVD-RETROHARDEN-004 | Repairability score computed |

## Test Summary

| Category | Count | Status |
|----------|-------|--------|
| Rust unit tests | 49 | All pass |
| Python verification checks | 83 | All pass |
| Python unit tests | 25 | All pass |

## Downstream Unblocked

- bd-1fp4: Integrity sweep escalation/de-escalation policy
- bd-3epz: Section 10.14 verification gate
- bd-5rh: 10.14 plan gate
