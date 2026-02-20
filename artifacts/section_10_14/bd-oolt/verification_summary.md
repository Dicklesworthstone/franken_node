# bd-oolt: Mandatory Evidence Emission — Verification Summary

**Section**: 10.14
**Bead**: bd-oolt
**Status**: PASS
**Agent**: CrimsonCrane
**Date**: 2026-02-20

## Deliverables

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_14/bd-oolt_contract.md` |
| Implementation | `crates/franken-node/src/policy/evidence_emission.rs` |
| Verification script | `scripts/check_evidence_emission.py` |
| Python unit tests | `tests/test_check_evidence_emission.py` |
| Evidence JSON | `artifacts/section_10_14/bd-oolt/verification_evidence.json` |

## Implementation Overview

Conformance middleware that requires evidence emission for all policy-driven
control actions (commit, abort, quarantine, release). Any action without a
valid evidence entry is rejected.

### Key Types

| Type | Purpose |
|------|---------|
| `PolicyAction` | Enum: Commit, Abort, Quarantine, Release |
| `ActionId` | Stable cross-reference identifier |
| `EvidenceRequirement` | Per-action evidence specification |
| `EvidenceConformanceChecker` | Middleware verifying evidence before execution |
| `PolicyActionOutcome` | Result: Executed or Rejected |
| `ConformanceError` | 5 error variants with stable error codes |
| `CoverageEntry` | Coverage matrix entry for all action types |

### Event Codes

| Code | Meaning |
|------|---------|
| EVD-POLICY-001 | Successful evidence-linked action |
| EVD-POLICY-002 | Missing evidence rejection |
| EVD-POLICY-003 | Evidence/action linkage mismatch |

### Invariants

| ID | Status |
|----|--------|
| INV-EVIDENCE-MANDATORY | Verified (all 4 actions require evidence) |
| INV-EVIDENCE-LINKAGE | Verified (action_id must match decision_id) |
| INV-EVIDENCE-COMPLETE | Verified (coverage matrix covers all DecisionKind variants) |

## Verification Results

| Metric | Count | Status |
|--------|-------|--------|
| Rust unit tests | 31 | All pass |
| Python verification checks | 64 | All pass |
| Python unit tests | 24 | All pass |

### Check Breakdown

- File existence: 2/2
- Module registration: 1/1
- Upstream dependency: 1/1
- Upstream imports: 1/1
- Test count: 1/1 (31 tests, minimum 25)
- Required types: 7/7
- Required methods: 10/10
- Event codes: 3/3
- Invariants: 3/3
- Action variants: 4/4
- Error codes: 5/5
- Required test names: 26/26

**Total: 64/64 PASS**

## Upstream Dependencies

- bd-2e73 (evidence ledger ring buffer): CLOSED

## Downstream Unblocked

- bd-1oof: Trace-witness references on high-impact entries
- bd-2ona: Replay validator
- bd-15j6: 10.15 mandatory ledger gate
- bd-3epz: Section 10.14 verification gate
- bd-5rh: 10.14 plan gate
