# bd-21fo Governor Conformance Discrepancies

This document records all known divergences from the bd-21fo specification in the `GovernorGate` implementation.

## Current Status: ZERO DIVERGENCES

As of 2026-05-22, there are **no known intentional divergences** from the bd-21fo specification.

## Future Divergence Tracking

If any intentional divergences are discovered or accepted, they will be documented here following this format:

### Template

## DISC-XXX: Short Description
- **Specification**: What the specification requires
- **Implementation**: What our implementation does instead
- **Impact**: Effect on behavior or compatibility
- **Resolution**: ACCEPTED | INVESTIGATING | WILL-FIX
- **Tests affected**: List of conformance tests expecting this behavior
- **Review date**: When this divergence should be re-evaluated

### Guidelines for Divergences

1. Every divergence gets a sequential ID (DISC-001, DISC-002, etc.)
2. Must state whether ACCEPTED, INVESTIGATING, or WILL-FIX
3. Must list affected conformance test cases
4. Must include review date (divergences can become stale)
5. Tests for accepted divergences use XFAIL, not SKIP
6. Must explain the business/technical justification

### Types of Acceptable Divergences

- **Error message format**: Different error text that conveys the same semantic meaning
- **Performance optimizations**: Behavior changes that improve performance without violating guarantees
- **Extended functionality**: Additional features beyond specification requirements
- **Platform differences**: Unavoidable platform-specific behavior variations

### Types of Unacceptable Divergences

- **Safety violations**: Any behavior that compromises the safety envelope invariant
- **Functional regressions**: Missing required functionality from the specification
- **Security weaknesses**: Implementation gaps that introduce security vulnerabilities
- **Compatibility breaks**: Changes that prevent interoperability

---

*Last updated: 2026-05-22*  
*Review schedule: Monthly during active development*  
*Next review: 2026-06-22*