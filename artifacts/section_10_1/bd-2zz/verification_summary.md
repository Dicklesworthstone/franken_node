# bd-2zz Verification Summary: Dependency-Direction Guard

## Bead
- **ID:** bd-2zz
- **Title:** [10.1] Add dependency-direction guard preventing local engine crate reintroduction
- **Section:** 10.1 (Charter + Split Governance)

## Deliverables

| Artifact | Path | Status |
|----------|------|--------|
| Spec/contract | `docs/specs/section_10_1/bd-2zz_contract.md` | Created |
| Guard script | `scripts/guard_dependency_direction.py` | Created |
| Unit tests (11 tests) | `tests/test_guard_dependency_direction.py` | All pass |
| Verification evidence | `artifacts/section_10_1/bd-2zz/verification_evidence.json` | Generated |

## Evidence Traceability

The machine-readable evidence now explicitly cites the implementation and
regression-test artifacts that produce and validate this guard:

- Guard implementation: `scripts/guard_dependency_direction.py`
- Regression tests: `tests/test_guard_dependency_direction.py`
- Spec contract: `docs/specs/section_10_1/bd-2zz_contract.md`

## Guard Checks

| Check ID | Invariant | Result |
|----------|----------|--------|
| GUARD-WS-MEMBERS | No engine crate dirs in workspace members | PASS |
| GUARD-PKG-NAMES | No local Cargo.toml declares engine package names | PASS |
| GUARD-DEP-DIR | Engine deps point outside this repo to /dp/franken_engine/ | PASS |
| GUARD-CRATES-CLEAN | No engine-named dirs in crates/ | PASS |

## Unit Test Results

11/11 tests passing. Tests verify JSON output, verdict, all check IDs, individual checks, human-readable output, summary counts, and checked-in evidence citations.

**Overall Verdict: PASS (4/4 checks, 11/11 tests)**
