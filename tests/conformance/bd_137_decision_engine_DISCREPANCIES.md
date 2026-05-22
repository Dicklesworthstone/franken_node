# bd-137 Policy Decision Engine Known Conformance Divergences

## Overview
This file documents intentional deviations from the decision engine specification.
Currently, there are **no known divergences** - all behavior matches specification.

## Divergence Registry
*No divergences recorded as of conformance harness creation.*

## Potential Future Divergences

### MONITORING-001: System guardrail test limitations  
- **Specification:** System guardrails should block all candidates when system state violations occur
- **Test limitation:** BD137-PREC-002 uses mock system state that may not trigger actual blocking
- **Impact:** Test validates structure but not actual blocking behavior  
- **Resolution:** ACCEPTABLE - actual guardrail blocking logic tested in bd_3a3q_guardrail_monitor_conformance.rs
- **Review date:** N/A (not yet a divergence)

## Test Skips vs. Divergences

| Test ID | Status | Reason | Classification |
|---------|--------|--------|----------------|
| BD137-PREC-002 | SKIP (conditional) | Mock system state may not trigger guardrails | Test limitation, not divergence |

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

## Last Updated
2026-05-22 - Initial conformance harness creation (CrimsonCrane cc_2)