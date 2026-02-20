# bd-28wj: Non-Negotiable Constraints — Verification Summary

**Section:** 4 | **Verdict:** PASS | **Date:** 2026-02-20

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Python verification checks | 84 | 84 |
| Python unit tests | 29 | 29 |

## Constraints Covered

All 13 non-negotiable constraints documented with:
- Enforcement mechanism (CI gate or review gate)
- Violation event code (`NNC-002:C-XX`)
- Severity classification (HARD or SOFT)
- Fix instructions for each violation

## Governance Artifacts

- Constraint reference: `docs/governance/non_negotiable_constraints.md`
- Waiver registry: `docs/governance/waiver_registry.json` (empty — no active waivers)
- Event codes: NNC-001 through NNC-004
- Invariants: INV-NNC-COMPLETE, INV-NNC-ACTIONABLE, INV-NNC-AUDITABLE, INV-NNC-NO-SILENT-EROSION

## Artifacts

- Spec: `docs/specs/section_4/bd-28wj_contract.md`
- Verification: `scripts/check_non_negotiable_constraints.py`
- Unit tests: `tests/test_check_non_negotiable_constraints.py`
