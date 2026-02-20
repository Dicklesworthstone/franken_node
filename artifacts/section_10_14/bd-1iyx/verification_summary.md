# bd-1iyx: Determinism Conformance Tests — Verification Summary

## Bead

| Field | Value |
|-------|-------|
| ID | bd-1iyx |
| Title | Add determinism conformance tests ensuring identical artifacts across replicas |
| Section | 10.14 |
| Status | Closed |

## What Was Built

Multi-replica determinism test harness that empirically validates byte-for-byte
identical outputs from N independent processing pipelines with identical inputs.
Includes divergence localization (offset, hex context, root-cause hinting) and
fixture-driven expected seed verification.

### Implementation

- **`tests/conformance/replica_artifact_determinism.rs`** — Harness with
  Divergence reporting, Replica simulation, FixtureResult tracking.
  19 harness-specific tests + 47 upstream seed tests = 66 total.

### Key Features

| Feature | Description |
|---------|-------------|
| Byte-for-byte comparison | Identical replica outputs verified |
| Divergence localization | First mismatch offset + 16-byte hex context |
| Root-cause hinting | Timestamp diffs, hash map ordering, length mismatches |
| Configurable replicas | Default 3, tested up to 10 |
| Expected seed verification | Cross-checks against fixture golden values |

### Event Codes

| Code | Description |
|------|-------------|
| DETERMINISM_CHECK_STARTED | Fixture test run begins |
| DETERMINISM_CHECK_PASSED | All replicas identical |
| DETERMINISM_CHECK_FAILED | Divergence detected |

## Test Summary

| Category | Count | Status |
|----------|-------|--------|
| Rust conformance tests | 19 | All pass |
| Rust total (incl. seed) | 66 | All pass |
| Python verification checks | 56 | All pass |
| Python unit tests | 15 | All pass |
| Fixture sets | 3 | All cross-validated |

## Artifacts

| Artifact | Path |
|----------|------|
| Test harness | `tests/conformance/replica_artifact_determinism.rs` |
| Test stub | `crates/franken-node/tests/replica_artifact_determinism.rs` |
| Fixtures | `fixtures/determinism/{small_encoding,medium_multi_domain,edge_case_minimal}.json` |
| Results CSV | `artifacts/10.14/determinism_conformance_results.csv` |
| Spec | `docs/specs/section_10_14/bd-1iyx_contract.md` |
| Evidence | `artifacts/section_10_14/bd-1iyx/verification_evidence.json` |
| Verification script | `scripts/check_determinism_conformance.py` |
| Script tests | `tests/test_check_determinism_conformance.py` |

## Downstream Unblocked

- bd-3epz: Section 10.14 verification gate
- bd-5rh: Section 10.14 parent tracking bead
