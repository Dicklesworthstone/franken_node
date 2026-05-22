# bd-3rya Hardening State Machine Known Conformance Divergences

## Overview
This file documents intentional deviations from the hardening state machine specification.
Currently, there are **no known divergences** - all behavior matches specification contracts.

## Divergence Registry
*No divergences recorded as of Round 45 conformance harness creation.*

## Potential Future Divergences

### GOVERNANCE-001: Governance rollback mechanism testing limitations
- **Specification:** Rollback requires valid signed governance artifact  
- **Test limitation:** BD3RYA-GOV-001 tests structure but not actual governance artifact verification
- **Impact:** Verifies that normal escalation API rejects regression, but doesn't test full governance flow
- **Resolution:** ACCEPTABLE - governance artifact verification requires separate cryptographic subsystem
- **Review date:** N/A (not yet a divergence)

### PERSISTENCE-001: Crash recovery testing simulation
- **Specification:** Committed level survives crash recovery
- **Test approach:** BD3RYA-DUR-001 simulates recovery by creating new state machine with same level
- **Impact:** Tests state preservation principle but not actual persistence mechanisms  
- **Resolution:** ACCEPTABLE - persistence layer is external to state machine core logic
- **Review date:** N/A (structural test sufficient)

### EVENT-EMISSION-001: Event code testing coverage
- **Specification:** Event codes should be emitted for transitions
- **Test coverage:** Tests verify event codes exist and map correctly to transitions
- **Impact:** Tests event code structure but not actual emission to logging infrastructure
- **Resolution:** ACCEPTABLE - testing API contracts, not event system implementation
- **Review date:** N/A (contract verification sufficient)

## Test Skips vs. Divergences

| Test ID | Status | Reason | Classification |
|---------|--------|--------|----------------|
| BD3RYA-EDGE-002 | MAY/SKIP (conditional) | Empty trace_id may be rejected by implementation | Implementation choice, not divergence |

## Divergence Review Process

1. **Detection:** Conformance test fails unexpectedly
2. **Analysis:** Determine if failure indicates:
   - Implementation bug (fix implementation)
   - Test bug (fix test)  
   - Intentional divergence (document here)
3. **Documentation:** If divergence, add entry with:
   - Sequential ID (DISC-NNN)
   - Impact assessment
   - Resolution status (ACCEPTED/INVESTIGATING/WILL-FIX)
   - Affected test cases
   - Review date
4. **Test marking:** Use XFAIL for accepted divergences, never SKIP

## Template for New Divergences

```markdown
## DISC-001: [Brief description]
- **Reference:** [What the specification says]
- **Our impl:** [What we actually do]
- **Impact:** [User-visible effects]
- **Resolution:** [ACCEPTED/INVESTIGATING/WILL-FIX] — [rationale]
- **Tests affected:** [List of test IDs]
- **Review date:** [YYYY-MM-DD]
```

## API Evolution Notes

### HardeningLevel Enum Stability
- Current levels: Baseline(0) < Standard(1) < Enhanced(2) < Maximum(3) < Critical(4)
- **Future additions:** New levels must maintain total ordering
- **Removal policy:** Levels cannot be removed once used (breaking change)
- **Conformance impact:** BD3RYA-LEVEL-001 must be updated for new levels

### Transition Mechanisms
- Current: escalate() for forward transitions, governance rollback for regression
- **Future extensions:** Additional transition types must preserve monotonicity invariant
- **Conformance impact:** New transition types need corresponding test cases

## Last Updated
2026-05-22 - Round 45 conformance harness creation (CrimsonCrane cc_2)