# bd-20uo Proof-Carrying Decode Conformance Discrepancies

This document tracks all known divergences between our bd-20uo implementation and the specification requirements.

## Current Status: FULLY CONFORMANT

As of 2026-05-22, our implementation shows **zero known divergences** from the bd-20uo specification requirements. All MUST and SHOULD clauses are implemented as specified.

## Future Discrepancy Recording

When divergences are identified, they will be documented using this template:

### DISC-XXX: Description
- **Specification:** What the bd-20uo spec requires
- **Our implementation:** How we differ
- **Impact:** Functional impact on interoperability or correctness  
- **Resolution:** ACCEPTED/INVESTIGATING/WILL-FIX
- **Tests affected:** List of test cases that expect this divergence
- **Review date:** When to revisit this decision
- **Justification:** Why this divergence is acceptable (if ACCEPTED)

## Specification Adherence Notes

Our implementation demonstrates strict adherence to bd-20uo across all tested areas:

- **Proof Generation**: All mandatory proof components included per INV-REPAIR-PROOF-COMPLETE
- **Proof Binding**: Cryptographic binding between fragments and attestations per INV-REPAIR-PROOF-BINDING  
- **Deterministic Behavior**: Consistent proof generation per INV-REPAIR-PROOF-DETERMINISTIC
- **Mode Handling**: Correct mandatory vs advisory behavior per specification
- **Event Emission**: All required event codes emitted at proper points
- **Error Handling**: All specified error conditions detected and reported
- **Capacity Management**: Proper handling of proof size limits
- **Unicode Support**: Correct processing of non-ASCII repair content

## Test Coverage Philosophy

We use XFAIL (expected failure) markers for any accepted divergences rather than SKIP markers. This ensures:
- Divergences remain visible in test reports
- We track when specification changes might resolve divergences
- Test coverage remains comprehensive even for divergent behavior