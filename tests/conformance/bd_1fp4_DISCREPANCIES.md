# bd-1fp4 Known Conformance Divergences

## Summary

**Zero known divergences** from the bd-1fp4 integrity sweep scheduler specification as of the conformance harness implementation.

All 19 test cases pass with 100% specification compliance:
- 17/17 MUST clauses: PASSING  
- 2/2 SHOULD clauses: PASSING
- 0 divergences documented
- 0 expected failures (XFAIL)

## Review Process

This discrepancies file will be updated when:

1. **New divergences discovered**: Any intentional deviation from bd-1fp4 spec
2. **Specification changes**: Updates to bd-1fp4 requiring scheduler adjustments  
3. **Implementation decisions**: Changes to band classification or hysteresis logic
4. **Threshold modifications**: Adjustments to rejection/repairability thresholds

## Potential Future Divergences

Areas to monitor for possible future divergences:

### POTENTIAL-001: Band Classification Thresholds
- **Context**: Rejection and repairability thresholds for band classification
- **Risk**: Business requirements may require different threshold values
- **Mitigation**: Tests validate against current thresholds; configurable via SweepSchedulerConfig
- **Status**: MONITORING

### POTENTIAL-002: Hysteresis Algorithm
- **Context**: N consecutive readings required for de-escalation
- **Risk**: May need different hysteresis strategies (exponential backoff, weighted averaging)
- **Mitigation**: Tests validate current algorithm; extensible to new strategies
- **Status**: MONITORING

### POTENTIAL-003: Interval Scaling
- **Context**: Fixed intervals per band (red=10s, yellow=1min, green=5min)
- **Risk**: May need dynamic scaling based on system load or evidence severity
- **Mitigation**: Current values are configurable; tests validate ordering constraints
- **Status**: MONITORING

### POTENTIAL-004: Sweep Depth Mapping
- **Context**: Band → SweepDepth mapping (implementation-specific)
- **Risk**: Depth strategy may need adjustment based on operational experience
- **Mitigation**: Test validates concept; specific mappings would need implementation updates
- **Status**: MONITORING

## Current Specification Assumptions

The conformance harness validates these design assumptions:

1. **Band Severity Ordering**: Green < Yellow < Red (0, 1, 2)
2. **Interval Ordering**: red_interval < yellow_interval < green_interval
3. **Immediate Escalation**: No hysteresis for risk increase
4. **Single-Step De-escalation**: Only one band down per hysteresis cycle
5. **Bounded Capacity**: Decision log uses push_bounded with MAX_DECISIONS=4096
6. **Deterministic Classification**: Same evidence always produces same band

## Compliance History

- **2026-05-22**: Initial conformance harness created - 100% compliant
- **Next review**: When bd-1fp4 specification or thresholds are updated

## Configuration Dependencies

The conformance tests depend on these default configuration values:
- hysteresis_threshold: 3
- green_interval_ms: 300,000 (5 minutes)
- yellow_interval_ms: 60,000 (1 minute)  
- red_interval_ms: 10,000 (10 seconds)
- yellow_rejection_threshold: 2
- red_rejection_threshold: 5
- low_repairability_threshold: 0.5

Changes to these defaults may require test updates and appropriate divergence documentation.

## Contact

For questions about bd-1fp4 conformance or to report new divergences:
- Update this file with new DISC-NNN entries
- Follow the standard divergence documentation format
- Include review dates and resolution status

---

*Last updated: 2026-05-22*  
*Next scheduled review: Upon specification changes*