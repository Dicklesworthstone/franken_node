# bd-2hrg: Impossible-by-Default Capability Index — Verification Summary

**Section:** 3.2 | **Verdict:** PASS | **Date:** 2026-02-20

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Python verification checks | 53 | 53 |
| Python unit tests | 13 | 13 |

## Capability Coverage

- **10 capabilities** (IBD-01 through IBD-10) with impossibility rationale
- **13 owner track mappings** across 10.2-10.21
- **3 category-creation tests** (uniqueness, verifiability, migration)
- **5 quantitative targets** (QT-01 through QT-05) with thresholds
- **4 event codes** (IBD-001 through IBD-004)
- **4 invariants** (INV-IBD-MAPPED, EVIDENCE, UNIQUE, COMPLETE)

## Artifacts

- Capabilities doc: `docs/doctrine/impossible_by_default_capabilities.md`
- Spec: `docs/specs/section_3_2/bd-2hrg_contract.md`
- Verification: `scripts/check_impossible_capabilities.py`
- Unit tests: `tests/test_check_impossible_capabilities.py`
