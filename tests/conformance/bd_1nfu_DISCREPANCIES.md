# bd-1nfu Remote Capability Gate Conformance Discrepancies

This document tracks all known divergences between our bd-1nfu implementation and the specification requirements.

## Current Status: FULLY CONFORMANT

As of 2026-05-22, our implementation shows **zero known divergences** from the bd-1nfu specification requirements. All MUST and SHOULD clauses are implemented as specified.

## Future Discrepancy Recording

When divergences are identified, they will be documented using this template:

### DISC-XXX: Description
- **Specification:** What the bd-1nfu spec requires
- **Our implementation:** How we differ
- **Impact:** Functional impact on capability gate enforcement or security
- **Resolution:** ACCEPTED/INVESTIGATING/WILL-FIX
- **Tests affected:** List of test cases that expect this divergence
- **Review date:** When to revisit this decision
- **Justification:** Why this divergence is acceptable (if ACCEPTED)

## Specification Adherence Notes

Our implementation demonstrates strict adherence to bd-1nfu across all tested areas:

- **Token Structure**: RemoteCap tokens contain all required fields (scope, issuer, expiry, signature) per specification
- **Gate Enforcement**: CapabilityGate serves as the single validation/enforcement point for all operations
- **Event Emission**: All specified event codes (REMOTECAP_ISSUED, REMOTECAP_DENIED, REMOTECAP_CONSUMED, etc.) emitted at proper points
- **Error Handling**: All specified error codes (REMOTECAP_MISSING, REMOTECAP_EXPIRED, REMOTECAP_INVALID_SIGNATURE, etc.)
- **Security Properties**: Signature verification prevents forgery, scope validation prevents unauthorized access
- **Replay Protection**: Single-use tokens cannot be replayed after consumption
- **Local Mode Support**: Local-only operations work without network capabilities when configured
- **Audit Trail**: Comprehensive structured audit events for all capability operations with required fields

## Test Coverage Philosophy

We use XFAIL (expected failure) markers for any accepted divergences rather than SKIP markers. This ensures:
- Divergences remain visible in test reports
- We track when specification changes might resolve divergences
- Test coverage remains comprehensive even for divergent behavior
- Security and correctness properties are never compromised by hidden test failures

## Implementation Quality Notes

Our bd-1nfu implementation includes several quality enhancements beyond the base specification:

### Enhanced Security
- Constant-time signature comparison using `crate::security::constant_time::ct_eq()`
- Strong secret material validation with entropy checks and weak secret detection
- Saturating arithmetic for all timestamp and counter operations
- Fail-closed behavior on cryptographic errors

### Improved Observability
- Both current and legacy event codes for backward compatibility
- Comprehensive trace ID propagation through all operations
- Detailed denial codes for precise error classification
- Structured audit events with machine-readable timestamps

### Operational Robustness
- Graceful handling of mutex contention in replay protection
- Configurable replay storage backends with environment variable overrides
- Local-only mode for air-gapped or offline operations
- Bounded audit log capacity with oldest-first eviction (bd-1xbr pattern)

These enhancements maintain full bd-1nfu compliance while providing additional operational benefits.