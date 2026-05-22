# bd-ncwlf Known Conformance Divergences

## Summary

**Zero known divergences** from the bd-ncwlf specification as of the conformance harness implementation.

All 20 test cases pass with 100% specification compliance:
- 16/16 MUST clauses: PASSING  
- 4/4 SHOULD clauses: PASSING
- 0 divergences documented
- 0 expected failures (XFAIL)

## Review Process

This discrepancies file will be updated when:

1. **New divergences discovered**: Any intentional deviation from bd-ncwlf spec
2. **Specification changes**: Updates to bd-ncwlf requiring test adjustments  
3. **Implementation decisions**: Choices that affect conformance behavior
4. **External dependencies**: Third-party library changes affecting compliance

## Potential Future Divergences

Areas to monitor for possible future divergences:

### POTENTIAL-001: RCH Worker Availability
- **Context**: Skip mode triggered by "no rch worker available"
- **Risk**: If rch execution environment changes, skip behavior may change
- **Mitigation**: Test suite uses mocked skip mode to avoid environment dependency
- **Status**: MONITORING

### POTENTIAL-002: Performance Measurement Precision
- **Context**: f64 arithmetic for performance calculations
- **Risk**: Floating-point precision differences across platforms
- **Mitigation**: Using epsilon comparisons for floating-point tests
- **Status**: MONITORING

### POTENTIAL-003: Default Case Evolution
- **Context**: `default_hot_path_budget_smoke_cases()` may evolve
- **Risk**: New hot paths added or existing ones modified
- **Mitigation**: Tests validate structure and behavior, not specific counts
- **Status**: MONITORING

## Compliance History

- **2026-05-22**: Initial conformance harness created - 100% compliant
- **Next review**: When bd-ncwlf specification is updated or implementation changes

## Contact

For questions about bd-ncwlf conformance or to report new divergences:
- Update this file with new DISC-NNN entries
- Follow the standard divergence documentation format
- Include review dates and resolution status

---

*Last updated: 2026-05-22*  
*Next scheduled review: Upon specification changes*