# bd-1iyx: Determinism Conformance Tests

## Overview

Multi-replica test harness that empirically validates determinism by running
N independent processing pipelines with identical inputs and comparing all
output artifacts byte-for-byte. Turns the determinism invariant from a design
aspiration into a CI-enforced guarantee.

## Module

`tests/conformance/replica_artifact_determinism.rs`

## Key Types

| Type | Purpose |
|------|---------|
| `Divergence` | Describes a single mismatch between replicas (offset, hex context, root cause) |
| `Replica` | Simulated independent processing pipeline |
| `FixtureResult` | Result of running a fixture across N replicas |

## Capabilities

- **Byte-for-byte comparison**: All replica outputs must be identical
- **Divergence localization**: Reports first mismatched byte offset with 16-byte hex context
- **Root-cause hinting**: Detects timestamp diffs, hash map ordering, length mismatches
- **Configurable replica count**: Default 3, tested up to 10
- **Expected seed verification**: Cross-checks against fixture golden values

## Fixtures

| Name | Domains | Config | Description |
|------|---------|--------|-------------|
| small_encoding | 3 | v1, basic erasure | Small chunk with erasure coding |
| medium_multi_domain | 5 | v2, multi-param | All domains, complex config |
| edge_case_minimal | 2 | v1, empty params | Single-bit content, empty config |

## Event Codes

| Code | Description |
|------|-------------|
| DETERMINISM_CHECK_STARTED | Fixture test run begins |
| DETERMINISM_CHECK_PASSED | All replicas produced identical outputs |
| DETERMINISM_CHECK_FAILED | Divergence detected between replicas |

## Artifacts

| Artifact | Path |
|----------|------|
| Test harness | `tests/conformance/replica_artifact_determinism.rs` |
| Test stub | `crates/franken-node/tests/replica_artifact_determinism.rs` |
| Fixtures | `fixtures/determinism/*.json` |
| Results CSV | `artifacts/10.14/determinism_conformance_results.csv` |
| Spec | `docs/specs/section_10_14/bd-1iyx_contract.md` |
| Verification script | `scripts/check_determinism_conformance.py` |
| Script tests | `tests/test_check_determinism_conformance.py` |
