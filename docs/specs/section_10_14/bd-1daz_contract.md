# bd-1daz: Retroactive Hardening Pipeline

**Section**: 10.14
**Module**: `crates/franken-node/src/policy/retroactive_hardening.rs`
**Depends on**: bd-3rya (hardening state machine), bd-2e73 (evidence ledger)

## Overview

When the system escalates its hardening level, objects created at a lower level
do not retroactively gain additional protections. This pipeline appends protection
artifacts (checksums, parity, integrity proofs, redundant copies) to existing
objects WITHOUT rewriting canonical object data. This is the union-only principle:
protection is additive, never destructive.

## Union-Only Principle

- The canonical object's `object_id`, `content_hash`, and `creation_level` are never modified.
- Protection artifacts are stored alongside canonical objects, never inside them.
- `verify_identity_stable()` confirms object identity is unchanged after hardening.

## Types

| Type | Purpose |
|------|---------|
| `CanonicalObject` | Object with stable identity: object_id, content_hash, creation_level, content |
| `ObjectId` | Unique identifier for canonical objects |
| `ProtectionType` | Enum: Checksum, Parity, IntegrityProof, RedundantCopy |
| `ProtectionArtifact` | Protection data appended alongside a canonical object |
| `RepairabilityScore` | Fraction (0.0-1.0) recoverable from protection artifacts |
| `RetroactiveHardeningPipeline` | Stateless pipeline that generates protection artifacts |
| `HardeningProgressRecord` | Per-object progress record: before/after repairability, artifacts_created |
| `HardeningResult` | Corpus-wide result: all artifacts, progress records, totals |

## Protection Types per Level

| Level | Protection Types |
|-------|-----------------|
| Baseline | (none) |
| Standard | Checksum |
| Enhanced | Checksum, Parity |
| Maximum | Checksum, Parity, IntegrityProof |
| Critical | Checksum, Parity, IntegrityProof, RedundantCopy |

## Repairability Weights

| Protection Type | Weight |
|-----------------|--------|
| Checksum | 0.10 |
| Parity | 0.20 |
| IntegrityProof | 0.15 |
| RedundantCopy | 0.50 |

Full coverage (all four types) sums to 0.95 (detection + recovery layers).

## Event Codes

| Code | Trigger |
|------|---------|
| EVD-RETROHARDEN-001 | Pipeline started (object count, from/to levels) |
| EVD-RETROHARDEN-002 | Object hardened (artifacts created count) |
| EVD-RETROHARDEN-003 | Identity verification passed |
| EVD-RETROHARDEN-004 | Repairability score computed |

## Invariants

| ID | Description |
|----|-------------|
| INV-RETROHARDEN-UNION-ONLY | Canonical object identity (hash, ID, content) unchanged after hardening |
| INV-RETROHARDEN-MONOTONIC | Repairability score can only increase (or stay at 1.0) after hardening |
| INV-RETROHARDEN-IDEMPOTENT | Re-hardening at same level produces no additional artifacts |
| INV-RETROHARDEN-BOUNDED | Pipeline memory is bounded by corpus size |

## Methods

| Method | Purpose |
|--------|---------|
| `fn harden()` | Generate protection artifacts for one object's level gap |
| `fn harden_corpus()` | Run hardening across a corpus of objects |
| `fn verify_identity_stable()` | Confirm object identity (ID + content_hash) unchanged |
| `fn measure_repairability()` | Compute repairability score from artifacts (deduplicates by type) |
| `fn required_protections()` | Returns protection types required at a given hardening level |

## Artifacts

| Artifact | Path |
|----------|------|
| Implementation | `crates/franken-node/src/policy/retroactive_hardening.rs` |
| Spec contract | `docs/specs/section_10_14/bd-1daz_contract.md` |
| Verification script | `scripts/check_retroactive_hardening.py` |
| Python unit tests | `tests/test_check_retroactive_hardening.py` |
| Hardening report | `artifacts/10.14/retroactive_hardening_report.json` |
| Verification evidence | `artifacts/section_10_14/bd-1daz/verification_evidence.json` |
| Verification summary | `artifacts/section_10_14/bd-1daz/verification_summary.md` |

## Dependencies

- **Upstream**: bd-3rya (HardeningLevel, state machine triggers pipeline), bd-2e73 (evidence ledger records progress)
- **Downstream**: bd-1fp4 (integrity sweep scheduler), bd-3epz (section gate), bd-5rh (plan gate)

## Acceptance Criteria

1. `RetroactiveHardeningPipeline::harden()` generates exactly the missing protection artifacts for a level gap; produces empty Vec when `to_level <= from_level`.
2. `harden_corpus()` processes all objects and returns per-object `HardeningProgressRecord` with `repairability_before <= repairability_after`.
3. `verify_identity_stable()` returns true iff both `object_id` and `content_hash` are unchanged.
4. `measure_repairability()` deduplicates by protection type and caps score at 1.0.
5. All four event codes (EVD-RETROHARDEN-001..004) are defined.
6. All four invariants (INV-RETROHARDEN-UNION-ONLY, MONOTONIC, IDEMPOTENT, BOUNDED) are documented in source.
7. Baseline requires no protections; Critical requires all four types.
8. Test count >= 40 unit tests in the implementation file.
9. Report artifact `artifacts/10.14/retroactive_hardening_report.json` contains per-object repairability scores before/after hardening.
