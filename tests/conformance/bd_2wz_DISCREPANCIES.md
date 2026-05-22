# bd-2wz Known Conformance Divergences

## Summary

**Zero known divergences** from the bd-2wz mode-band matrix specification as of the conformance harness implementation.

All 13 test cases pass with 100% specification compliance:
- 12/12 MUST clauses: PASSING  
- 1/1 SHOULD clauses: PASSING
- 0 divergences documented
- 0 expected failures (XFAIL)

## Review Process

This discrepancies file will be updated when:

1. **New divergences discovered**: Any intentional deviation from bd-2wz spec
2. **Specification changes**: Updates to bd-2wz requiring matrix adjustments  
3. **Implementation decisions**: Changes to band/mode definitions or matrix behavior
4. **Matrix modifications**: Any alterations to the (band, mode) → action mapping

## Potential Future Divergences

Areas to monitor for possible future divergences:

### POTENTIAL-001: Matrix Cell Modifications
- **Context**: Specific (band, mode) → action mappings in the matrix
- **Risk**: Business requirements may require different actions for certain combinations
- **Mitigation**: Tests validate against current specification; would need updates if matrix changes
- **Status**: MONITORING

### POTENTIAL-002: New Band Categories
- **Context**: Addition of new CompatibilityBand variants
- **Risk**: New bands would require matrix extension and priority ordering definition
- **Mitigation**: Tests enumerate all current bands; extensible to new variants
- **Status**: MONITORING

### POTENTIAL-003: New Mode Categories
- **Context**: Addition of new CompatibilityMode variants
- **Risk**: New modes would require matrix extension and restrictiveness ordering
- **Mitigation**: Tests enumerate all current modes; extensible to new variants
- **Status**: MONITORING

### POTENTIAL-004: Action Type Extensions
- **Context**: Addition of new DivergenceAction variants
- **Risk**: New actions would require restrictiveness comparison logic updates
- **Mitigation**: Helper function isolates comparison logic; can be extended
- **Status**: MONITORING

## Current Matrix Specification

The conformance harness validates against this exact matrix:

| Band \\ Mode | Strict | Balanced | LegacyRisky |
|--------------|:------:|:--------:|:-----------:|
| **Core** | Error | Error | Error |
| **HighValue** | Error | Warn | Warn |
| **Edge** | Warn | Log | Log |
| **Unsafe** | Blocked | Blocked | Warn |

Any changes to this matrix would require:
1. Specification update documentation
2. Test case updates to reflect new behavior
3. Divergence documentation if changes affect compatibility

## Compliance History

- **2026-05-22**: Initial conformance harness created - 100% compliant
- **Next review**: When bd-2wz specification or matrix is updated

## Design Assumptions

The conformance harness makes these assumptions about the specification:

1. **Matrix Completeness**: Every (band, mode) combination has exactly one defined action
2. **Core Band Primacy**: Core band always returns Error regardless of mode
3. **Restrictiveness Ordering**: Error > Blocked > Warn > Log in terms of restrictiveness
4. **Determinism**: Function is pure with no side effects or state dependencies
5. **Enum Stability**: Band and mode enums maintain their current ordering relationships

If any of these assumptions change, the conformance tests will need updates and appropriate divergence documentation.

## Contact

For questions about bd-2wz conformance or to report new divergences:
- Update this file with new DISC-NNN entries
- Follow the standard divergence documentation format
- Include review dates and resolution status

---

*Last updated: 2026-05-22*  
*Next scheduled review: Upon specification changes*