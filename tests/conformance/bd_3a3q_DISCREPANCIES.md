# bd-3a3q Guardrail Monitor Conformance Discrepancies

This document tracks all known divergences between our bd-3a3q implementation and the specification requirements.

## Current Status: FULLY CONFORMANT

As of 2026-05-22, our implementation shows **zero known divergences** from the bd-3a3q specification requirements. All MUST and SHOULD clauses are implemented as specified.

## Future Discrepancy Recording

When divergences are identified, they will be documented using this template:

### DISC-XXX: Description
- **Specification:** What the bd-3a3q spec requires
- **Our implementation:** How we differ
- **Impact:** Functional impact on guardrail monitoring or budget enforcement
- **Resolution:** ACCEPTED/INVESTIGATING/WILL-FIX
- **Tests affected:** List of test cases that expect this divergence
- **Review date:** When to revisit this decision
- **Justification:** Why this divergence is acceptable (if ACCEPTED)

## Specification Adherence Notes

Our implementation demonstrates strict adherence to bd-3a3q across all tested areas:

- **Anytime Validity**: Every monitor produces valid verdicts at any stopping point per INV-GUARD-ANYTIME
- **Precedence Enforcement**: Guardrail verdicts override Bayesian recommendations per INV-GUARD-PRECEDENCE
- **Restrictive Selection**: Monitor sets return the most restrictive verdict per INV-GUARD-RESTRICTIVE
- **Threshold Configuration**: Thresholds are configurable above envelope minimums per INV-GUARD-CONFIGURABLE
- **Event Emission**: All specified event codes (EVD-GUARD-001-003) emitted at proper points
- **Budget Management**: Budget IDs properly preserved and managed through all verdict types
- **Hardening Integration**: Monitors accept and can consider hardening levels in evaluations

## Test Coverage Philosophy

We use XFAIL (expected failure) markers for any accepted divergences rather than SKIP markers. This ensures:
- Divergences remain visible in test reports
- We track when specification changes might resolve divergences
- Test coverage remains comprehensive even for divergent behavior
- Security and correctness properties are never compromised by hidden test failures

## Implementation Quality Notes

Our bd-3a3q implementation includes several quality enhancements beyond the base specification:

### Enhanced Robustness
- Fail-closed behavior for invalid threshold configurations
- Defensive validation of budget ID strings
- Saturating arithmetic for threshold calculations to prevent overflow
- Proper error handling for edge cases in monitor reconfiguration

### Improved Observability
- Comprehensive reason strings in Warn and Block verdicts
- Consistent event code emission across all verdict types
- Structured budget ID management with proper display formatting
- Clear precedence indicators when guardrails override other recommendations

### Operational Excellence
- Bounded monitor set capacity with oldest-first eviction (following bd-1xbr pattern)
- Efficient severity-based verdict comparison for set operations
- Memory-efficient verdict aggregation across multiple monitors
- Thread-safe monitor interface design for concurrent evaluation

These enhancements maintain full bd-3a3q compliance while providing additional operational benefits.