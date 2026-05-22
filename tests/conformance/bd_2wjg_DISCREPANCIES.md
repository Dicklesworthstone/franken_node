# bd-2wjg Known Conformance Divergences

## Summary

**Zero known divergences** from the bd-2wjg timing instrumentation specification as of the conformance harness implementation.

All 21 test cases pass with 100% specification compliance:
- 18/18 MUST clauses: PASSING  
- 3/3 SHOULD clauses: PASSING
- 0 divergences documented
- 0 expected failures (XFAIL)

## Review Process

This discrepancies file will be updated when:

1. **New divergences discovered**: Any intentional deviation from bd-2wjg spec
2. **Specification changes**: Updates to bd-2wjg requiring test adjustments  
3. **Implementation decisions**: Choices that affect timing instrumentation behavior
4. **Algorithm modifications**: Changes to percentile calculation or event emission

## Potential Future Divergences

Areas to monitor for possible future divergences:

### POTENTIAL-001: Floating-Point Precision
- **Context**: f64 arithmetic in percentile calculations and timing measurements
- **Risk**: Platform-specific floating-point differences in edge cases
- **Mitigation**: Tests use epsilon comparisons and avoid exact equality checks
- **Status**: MONITORING

### POTENTIAL-002: Bounded Capacity Behavior
- **Context**: MAX_TIMING_SAMPLES = 8192 limit enforcement via push_bounded()
- **Risk**: Changes to push_bounded() implementation affecting eviction strategy
- **Mitigation**: Tests verify capacity limits without depending on specific eviction order
- **Status**: MONITORING

### POTENTIAL-003: Event Emission Order
- **Context**: PRF-006/PRF-007/PRF-008 event ordering during complex operations
- **Risk**: Concurrent access or batching changes affecting event sequence
- **Mitigation**: Tests verify event presence and content, not strict ordering
- **Status**: MONITORING

### POTENTIAL-004: Percentile Algorithm Evolution
- **Context**: Nearest-rank percentile calculation may be replaced with interpolation
- **Risk**: Algorithm change would affect all percentile calculations
- **Mitigation**: Tests validate against nearest-rank specification; would need updates if algorithm changes
- **Status**: MONITORING

## Compliance History

- **2026-05-22**: Initial conformance harness created - 100% compliant
- **Next review**: When bd-2wjg specification is updated or implementation changes

## Algorithm Specifications

### Nearest-Rank Percentile Calculation
The conformance harness validates against the **nearest-rank method**:
```
index = ceil(percentile * count) - 1
result = sorted_samples[min(index, count - 1)]
```

This is the current specification requirement. If the algorithm changes to use interpolation or other methods, the conformance tests will need updates and appropriate divergence documentation.

## Contact

For questions about bd-2wjg conformance or to report new divergences:
- Update this file with new DISC-NNN entries
- Follow the standard divergence documentation format
- Include review dates and resolution status

---

*Last updated: 2026-05-22*  
*Next scheduled review: Upon specification changes*