# bd-1xwz Performance Budget Guard Conformance Discrepancies

This document tracks all known divergences between our bd-1xwz implementation and the specification requirements.

## Current Status: FULLY CONFORMANT

As of 2026-05-22, our implementation shows **zero known divergences** from the bd-1xwz specification requirements. All MUST and SHOULD clauses are implemented as specified.

## Future Discrepancy Recording

When divergences are identified, they will be documented using this template:

### DISC-XXX: Description
- **Specification:** What the bd-1xwz spec requires
- **Our implementation:** How we differ
- **Impact:** Functional impact on performance budget enforcement or regression detection
- **Resolution:** ACCEPTED/INVESTIGATING/WILL-FIX
- **Tests affected:** List of test cases that expect this divergence
- **Review date:** When to revisit this decision
- **Justification:** Why this divergence is acceptable (if ACCEPTED)

## Specification Adherence Notes

Our implementation demonstrates strict adherence to bd-1xwz across all tested areas:

- **Budget Enforcement**: Every hot path check compares against policy budget per INV-PBG-BUDGET-ENFORCED
- **Regression Blocking**: Measurements exceeding budgets block the gate per INV-PBG-REGRESSION-BLOCKED
- **Flamegraph Capture**: Evidence captured on every gate failure per INV-PBG-FLAMEGRAPH-ON-FAIL
- **Report Generation**: Structured reports always emitted per INV-PBG-REPORT-ALWAYS
- **Event Emission**: All specified event codes (PRF_001-008) emitted at proper points
- **Error Handling**: All specified error codes (ERR_BUDGET_EXCEEDED, ERR_NO_MEASUREMENTS, etc.)
- **Fail-Closed Boundaries**: Exact budget boundary values correctly fail closed
- **Path Traversal Protection**: Flamegraph paths properly validated for security
- **CSV Format**: Structured CSV reports with correct schema for machine consumption

## Test Coverage Philosophy

We use XFAIL (expected failure) markers for any accepted divergences rather than SKIP markers. This ensures:
- Divergences remain visible in test reports
- We track when specification changes might resolve divergences
- Test coverage remains comprehensive even for divergent behavior
- Performance regression detection is never compromised by hidden test failures