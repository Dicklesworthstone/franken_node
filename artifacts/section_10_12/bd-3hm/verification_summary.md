# bd-3hm Verification Summary

**Bead:** bd-3hm
**Section:** 10.12 (Ecosystem Fabric + Network Effects)
**Title:** Migration Singularity Artifact Contract and Verifier Format
**Verdict:** PASS
**Timestamp:** 2026-02-21T05:00:00Z

## Overview

This bead defines the artifact contract for migration singularity: a structured,
versioned format for migration outputs including rollback receipts, confidence
intervals, precondition proofs, and verifier-friendly validation metadata.

## Deliverables

| Deliverable              | Path                                                              | Status |
|--------------------------|-------------------------------------------------------------------|--------|
| Rust implementation      | `crates/franken-node/src/connector/migration_artifact.rs`         | PASS   |
| JSON Schema              | `spec/migration_artifact_schema.json`                             | PASS   |
| Reference vectors        | `vectors/migration_artifacts.json`                                | PASS   |
| Spec contract            | `docs/specs/section_10_12/bd-3hm_contract.md`                    | PASS   |
| Gate script              | `scripts/check_migration_artifacts.py`                            | PASS   |
| Test file                | `tests/test_check_migration_artifacts.py`                         | PASS   |
| Verification evidence    | `artifacts/section_10_12/bd-3hm/verification_evidence.json`       | PASS   |
| Verification summary     | `artifacts/section_10_12/bd-3hm/verification_summary.md`          | PASS   |

## Invariant Coverage

- INV-MA-SIGNED: Validated via `validate_artifact` -- empty signature rejected.
- INV-MA-ROLLBACK-PRESENT: Validated -- empty rollback receipt fields rejected.
- INV-MA-CONFIDENCE-CALIBRATED: Validated -- probability outside [0,1] rejected.
- INV-MA-VERSIONED: Validated -- unsupported schema versions rejected.
- INV-MA-VERIFIER-COMPLETE: Validated -- empty replay refs or state hashes rejected.
- INV-MA-DETERMINISTIC: Validated -- BTreeMap-based serialization produces identical hashes.

## Event Code Coverage

All event codes MA-001 through MA-008 are defined and tested.

## Error Code Coverage

All error codes ERR_MA_INVALID_SCHEMA, ERR_MA_SIGNATURE_INVALID, ERR_MA_MISSING_ROLLBACK,
ERR_MA_CONFIDENCE_LOW, and ERR_MA_VERSION_UNSUPPORTED are defined and exercised in tests.

## Test Results

- Rust unit tests: 40 tests, all passing
- Gate script checks: 50+ checks, all passing
- Python test suite: all tests passing
