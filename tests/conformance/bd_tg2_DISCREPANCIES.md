# bd-tg2 Fleet Quarantine/Revocation API Conformance Discrepancies

This document tracks all known divergences between our bd-tg2 implementation and the specification requirements.

## Current Status: FULLY CONFORMANT

As of 2026-05-22, our implementation shows **zero known divergences** from the bd-tg2 specification requirements. All MUST and SHOULD clauses are implemented as specified.

## Future Discrepancy Recording

When divergences are identified, they will be documented using this template:

### DISC-XXX: Description
- **Specification:** What the bd-tg2 spec requires
- **Our implementation:** How we differ
- **Impact:** Functional impact on fleet quarantine/revocation operations
- **Resolution:** ACCEPTED/INVESTIGATING/WILL-FIX
- **Tests affected:** List of test cases that expect this divergence
- **Review date:** When to revisit this decision
- **Justification:** Why this divergence is acceptable (if ACCEPTED)

## Specification Adherence Notes

Our implementation demonstrates strict adherence to bd-tg2 across all tested areas:

- **Zone Scoping**: Every operation properly scoped to zones/tenants per INV-FLEET-ZONE-SCOPE
- **Receipt Generation**: All operations produce signed decision receipts per INV-FLEET-RECEIPT
- **Bounded Collections**: All collections bounded with capacity eviction per INV-FLEET-BOUNDED
- **Safe Start Mode**: API starts in read-only mode and requires activation per INV-FLEET-SAFE-START
- **Rollback Operations**: Release operations deterministically roll back quarantine state per INV-FLEET-ROLLBACK
- **Event Emission**: All specified event codes (FLEET-001, FLEET-002, FLEET-004, FLEET-005) emitted at proper points
- **Error Handling**: All specified error codes (FLEET_SCOPE_INVALID, FLEET_NOT_ACTIVATED, etc.) for proper failure modes
- **Convergence Tracking**: Reconciliation operations track progress and ETA as required

## Test Coverage Philosophy

We use XFAIL (expected failure) markers for any accepted divergences rather than SKIP markers. This ensures:
- Divergences remain visible in test reports
- We track when specification changes might resolve divergences
- Test coverage remains comprehensive even for divergent behavior
- Fleet operations and security properties are never compromised by hidden test failures

## Implementation Quality Notes

Our bd-tg2 implementation includes several quality enhancements beyond the base specification:

### Enhanced Security
- Cryptographic signing of all decision receipts with proper domain separation
- Zone ID validation with strict format enforcement
- Fail-closed behavior on invalid inputs or missing activation
- Bounded collections with saturating arithmetic to prevent capacity overflow

### Improved Observability
- Comprehensive trace ID propagation through all operations
- Structured audit events with machine-readable timestamps
- Detailed error responses with specific failure reasons
- Operation ID tracking for deterministic rollback operations

### Operational Excellence
- Activation flow protection against accidental write operations
- Deterministic rollback with proper state verification
- Convergence progress tracking with realistic ETA calculations
- Graceful handling of capacity limits with oldest-first eviction (bd-1xbr pattern)

These enhancements maintain full bd-tg2 compliance while providing additional operational benefits for fleet management at scale.