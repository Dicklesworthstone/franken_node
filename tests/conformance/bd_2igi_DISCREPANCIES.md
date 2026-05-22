# bd-2igi Bayesian Posterior Diagnostics Known Conformance Divergences

## Overview
This file documents intentional deviations from the Bayesian posterior diagnostics specification.
Currently, there are **no known divergences** - all behavior matches specification contracts.

## Divergence Registry
*No divergences recorded as of Round 46 conformance harness creation.*

## Potential Future Divergences

### FLOATING-POINT-001: Bit-identical reproducibility limitations
- **Specification:** replay_from with identical observations produces bit-identical rankings
- **Test coverage:** BD2IGI-REPRO-001 uses bit-identical floating-point comparisons
- **Impact:** Different compiler optimizations or hardware could affect reproducibility
- **Resolution:** ACCEPTABLE - specification requires determinism within reasonable implementation bounds
- **Review date:** N/A (not yet a divergence)

### NORMALIZATION-001: Floating-point tolerance requirements
- **Specification:** Posterior probabilities sum to 1.0 within floating-point tolerance
- **Test tolerance:** Currently uses 1e-10 tolerance for normalization verification
- **Impact:** Very small numerical errors might exceed tolerance on some platforms
- **Resolution:** ACCEPTABLE - tolerance is appropriate for 64-bit floating-point precision
- **Review date:** N/A (working within specification bounds)

### CONFIDENCE-INTERVAL-001: Statistical accuracy vs. implementation efficiency
- **Specification:** Confidence intervals provided for transparency
- **Test approach:** Verifies interval contains mean and has proper bounds
- **Impact:** Tests structural properties but not statistical accuracy of 95% coverage
- **Resolution:** ACCEPTABLE - testing API contracts, not statistical theory validation
- **Review date:** N/A (appropriate scope limitation)

## Test Skips vs. Divergences

| Test ID | Status | Reason | Classification |
|---------|--------|--------|----------------|
| *None* | - | - | All tests designed to pass |

## Future API Evolution Considerations

### Observation Types
- Current: Boolean success/failure observations only
- **Future extensions:** Weighted observations, multi-outcome observations
- **Conformance impact:** New observation types must preserve normalization invariant

### Ranking Algorithms  
- Current: Beta-Bernoulli conjugate Bayesian updates
- **Future algorithms:** Non-conjugate methods, ensemble approaches
- **Conformance impact:** All algorithms must satisfy four core invariants

### Confidence Estimation
- Current: Beta distribution 95% credible intervals
- **Future methods:** Bootstrap confidence, Bayesian credible intervals at other levels
- **Conformance impact:** Confidence information must remain transparent

## Specification Interpretation Notes

### Advisory Nature Definition
- **INV-BAYES-ADVISORY** interpreted as: ranking methods take immutable references and return diagnostic data only
- **No side effects:** Methods don't modify external state or trigger actions
- **Pure computation:** Ranking is purely functional transformation of observations

### Reproducibility Scope
- **INV-BAYES-REPRODUCIBLE** applies to: same observation sequence → same ranking
- **Deterministic ordering:** BTreeMap ensures consistent iteration order for candidates
- **Bit-identical requirement:** Applies within same execution environment/platform

### Transparency Requirements
- **INV-BAYES-TRANSPARENT** includes: posterior, prior, count, confidence interval, guardrail status
- **Sufficient detail:** Users can understand and verify ranking decisions
- **No internal exposure:** Implementation details (alpha/beta values) not required

## Divergence Review Process

1. **Detection:** Conformance test fails unexpectedly or specification interpretation differs
2. **Analysis:** Determine if issue indicates:
   - Implementation bug (fix implementation)
   - Test bug (fix test)  
   - Specification ambiguity (clarify with stakeholders)
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

## Mathematical Considerations

### Numerical Stability
- **Floating-point arithmetic:** Standard IEEE 754 behavior assumed
- **Summation order:** Uses iterator order for reproducibility
- **Tolerance selection:** 1e-10 chosen for 64-bit precision with safety margin

### Statistical Properties
- **Beta distribution:** Standard conjugate prior for Bernoulli likelihood
- **Confidence intervals:** 95% credible intervals using quantile function
- **Prior selection:** Uniform prior (1/n) for n candidates when no observations

## Last Updated
2026-05-22 - Round 46 conformance harness creation (CrimsonCrane cc_2)