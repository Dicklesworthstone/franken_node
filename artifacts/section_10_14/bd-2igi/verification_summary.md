# bd-2igi: Verification Summary

## Bayesian Posterior Diagnostics for Explainable Policy Ranking

**Section:** 10.14 (FrankenSQLite Deep-Mined Expansion)
**Status:** PASS (64/64 checks)
**Agent:** CrimsonCrane (claude-code, claude-sonnet-4-6)
**Date:** 2026-02-20

## Implementation

- **Module:** `crates/franken-node/src/policy/bayesian_diagnostics.rs`
- **Spec:** `docs/specs/section_10_14/bd-2igi_contract.md`
- **Verification:** `scripts/check_bayesian_diagnostics.py`
- **Test Suite:** `tests/test_check_bayesian_diagnostics.py` (48 tests)
- **Diagnostics Report:** `artifacts/10.14/posterior_diagnostics_report.json`

## Architecture

| Type | Purpose |
|------|---------|
| `BayesianDiagnostics` | Core engine: update with observations, rank candidates |
| `CandidateRef` | Stable string reference to a policy action candidate |
| `Observation` | Evidence record: candidate, success flag, epoch_id |
| `RankedCandidate` | Annotated candidate with posterior_prob, prior_prob, CI, guardrail flag |
| `DiagnosticConfidence` | Low/Medium/High based on total observation count |
| `BetaState` | Internal Beta(alpha, beta) conjugate distribution state |

## Key Properties

- **Beta conjugate update**: alpha = successes + 1, beta = failures + 1 (uniform prior Beta(1,1))
- **BTreeMap ordering**: Deterministic iteration ensures reproducible rankings across runs
- **Normalized posteriors**: Raw beta means normalized so they sum to 1.0 (INV-BAYES-NORMALIZED)
- **95% credible interval**: Normal approximation on Beta distribution, clamped to [0, 1]
- **Advisory only**: Rankings never directly trigger actions (INV-BAYES-ADVISORY)
- **Guardrail integration**: `guardrail_filtered` flag marks blocked candidates without reordering
- **Full transparency**: Every RankedCandidate exposes posterior, prior, count, CI (INV-BAYES-TRANSPARENT)

## Event Codes

| Code | Trigger |
|------|---------|
| EVD-BAYES-001 | Posterior updated with new observation |
| EVD-BAYES-002 | Ranking produced (includes top candidate and confidence) |
| EVD-BAYES-003 | Guardrail conflict detected on top-ranked candidate |
| EVD-BAYES-004 | Replay from stored observations completed |

## Invariants

| ID | Status |
|----|--------|
| INV-BAYES-ADVISORY | Verified (diagnostics never execute actions) |
| INV-BAYES-REPRODUCIBLE | Verified (bit-identical rankings via BTreeMap + sequential replay) |
| INV-BAYES-NORMALIZED | Verified (posterior sums to 1.0 within 1e-10 tolerance) |
| INV-BAYES-TRANSPARENT | Verified (all ranking fields populated in every RankedCandidate) |

## Diagnostics Report Scenarios

| Scenario | Description | Confidence |
|----------|-------------|------------|
| `uniform_prior` | 3 candidates, no observations — equal posteriors | Low |
| `strong_preference` | 3 candidates, A:80%, B:50%, C:20% success over 20 obs each | High |
| `guardrail_conflict` | Top candidate A blocked; EVD-BAYES-003 fires; operator uses B | High |

## Test Summary

| Category | Count | Status |
|----------|-------|--------|
| Rust unit tests | 31 | All pass |
| Python verification checks | 64 | All pass |
| Python unit tests | 48 | All pass |

## Downstream Unblocked

- bd-15u3: Guardrail precedence over Bayesian recommendations
- bd-3epz: Section 10.14 verification gate
