# bd-29r6: Content-Derived Deterministic Seed Derivation — Verification Summary

## Bead

| Field | Value |
|-------|-------|
| ID | bd-29r6 |
| Title | Implement content-derived deterministic seed derivation for encoding/repair schedules |
| Section | 10.14 |
| Status | Closed |

## What Was Built

Domain-separated deterministic seed derivation using SHA-256 for encoding/repair
scheduling. Identical `(domain, content_hash, config)` tuples always produce
identical seeds. Supports INV-SEED-STABLE, INV-SEED-DOMAIN-SEP, INV-SEED-BOUNDED,
and INV-SEED-NO-PLATFORM.

### Implementation

- **`crates/franken-node/src/encoding/deterministic_seed.rs`** — DeterministicSeedDeriver,
  derive_seed(), golden vector tests, 47 unit tests.

### Key Types

| Type | Purpose |
|------|---------|
| `DomainTag` | 5-variant enum for domain separation (Encoding, Repair, Scheduling, Placement, Verification) |
| `ContentHash` | 32-byte pre-computed content hash |
| `ScheduleConfig` | Versioned BTreeMap config with deterministic hashing |
| `DeterministicSeed` | 32-byte derived seed with metadata |
| `DeterministicSeedDeriver` | Stateful wrapper with version bump tracking |
| `VersionBumpRecord` | Config change audit record |

### Algorithm

`SHA-256(domain_prefix || 0x00 || content_hash || config_hash)`

### Event Codes

| Code | Description |
|------|-------------|
| SEED_DERIVED | Seed successfully derived |
| SEED_VERSION_BUMP | Config change detected, bump recorded |

## Test Summary

| Category | Count | Status |
|----------|-------|--------|
| Rust unit tests | 47 | All pass |
| Python verification checks | 67 | All pass |
| Python unit tests | 21 | All pass |
| Golden derivation vectors | 12 | All cross-validated (Rust + Python) |

## Artifacts

| Artifact | Path |
|----------|------|
| Implementation | `crates/franken-node/src/encoding/deterministic_seed.rs` |
| Spec | `docs/specs/section_10_14/bd-29r6_contract.md` |
| Evidence | `artifacts/section_10_14/bd-29r6/verification_evidence.json` |
| Golden vectors | `artifacts/10.14/seed_derivation_vectors.json` |
| Verification script | `scripts/check_deterministic_seed.py` |
| Script tests | `tests/test_check_deterministic_seed.py` |

## Downstream Unblocked

- bd-1iyx: Determinism conformance tests
- bd-3epz: Section 10.14 verification gate
- bd-5rh: Section 10.14 parent tracking bead
