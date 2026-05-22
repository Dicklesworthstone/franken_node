# bd-w0jq Degraded-mode Audit Conformance Discrepancies

This document tracks all known divergences between our bd-w0jq implementation and the specification requirements.

## Current Status: FULLY CONFORMANT

As of 2026-05-22, our implementation shows **zero known divergences** from the bd-w0jq specification requirements. All MUST and SHOULD clauses are implemented as specified.

## Future Discrepancy Recording

When divergences are identified, they will be documented using this template:

### DISC-XXX: Description
- **Specification:** What the bd-w0jq spec requires
- **Our implementation:** How we differ
- **Impact:** Functional impact on audit trail integrity or compliance
- **Resolution:** ACCEPTED/INVESTIGATING/WILL-FIX
- **Tests affected:** List of test cases that expect this divergence
- **Review date:** When to revisit this decision
- **Justification:** Why this divergence is acceptable (if ACCEPTED)

## Specification Adherence Notes

Our implementation demonstrates strict adherence to bd-w0jq across all tested areas:

- **Schema Validation**: All required fields enforced per INV-DM-SCHEMA-COMPLETE
- **Event Type Enforcement**: Exact match for "degraded_mode_override" required
- **Immutability**: Events cannot be modified after append per INV-DM-IMMUTABLE
- **Correlation**: Exact action_id and trace_id matching per INV-DM-CORRELATION
- **Error Handling**: All specified error codes (DM_MISSING_FIELD, DM_EVENT_NOT_FOUND, DM_SCHEMA_VIOLATION)
- **Validation Before Append**: Schema validation always occurs before log append per INV-DM-EVENT-REQUIRED
- **Whitespace Handling**: Whitespace-only fields correctly rejected as empty
- **Case Sensitivity**: Lookups are exact and case-sensitive as expected

## Test Coverage Philosophy

We use XFAIL (expected failure) markers for any accepted divergences rather than SKIP markers. This ensures:
- Divergences remain visible in test reports
- We track when specification changes might resolve divergences  
- Test coverage remains comprehensive even for divergent behavior
- Audit trail compliance is never compromised by hidden test failures