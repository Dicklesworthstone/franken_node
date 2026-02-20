# bd-1w78 Contract: Continuous Lockstep Validation

**Section:** 13 — Success Criterion
**Bead:** bd-1w78
**Status:** in-progress
**Created:** 2026-02-20

## Purpose

Continuous lockstep validation ensures that franken_node maintains behavioral
parity with upstream Node.js and Bun runtimes. A lockstep comparison suite runs
on every CI push, compares outputs across all three engines, detects divergences
within strict latency bounds, and blocks any merge that introduces an undetected
regression.

## Targets

| Metric | Threshold |
|---|---|
| Compatibility corpus pass rate | >= 95% |
| Divergence detection latency | < 100 ms per test case |
| Undetected regressions merged | 0 (zero tolerance) |
| Minimum corpus size | >= 1000 test cases |

## Lockstep Architecture

The lockstep oracle operates in two layers:

- **L1 (Product Layer):** Drives the three runtimes (Node, Bun, franken_node)
  with identical inputs drawn from the compatibility corpus. Captures stdout,
  stderr, exit code, timing, and observable side-effects.
- **L2 (Engine Layer):** Compares L1 outputs using structured diff rules.
  Classifies each divergence and emits the appropriate event code.

## Event Codes

| Code | Name | Description |
|---|---|---|
| CLV-001 | lockstep_run_completed | A full lockstep comparison run finished successfully. |
| CLV-002 | divergence_detected | A behavioral divergence was found between runtimes. |
| CLV-003 | regression_blocked | A merge was blocked because it introduced a regression. |
| CLV-004 | corpus_updated | The compatibility corpus was updated (added/removed cases). |

## Invariants

### INV-CLV-CONTINUOUS
Lockstep validation MUST execute on every CI push to any branch that targets
the main integration branch. No push may bypass the lockstep gate.

### INV-CLV-COVERAGE
The compatibility corpus MUST cover at least 95% of the public API surface
enumerated in the franken_node capability map (Sections 10.2-10.13). The pass
rate across the corpus MUST be >= 95% for the gate to pass.

### INV-CLV-REGRESSION
Zero undetected regressions may be merged. Any divergence classified as
"blocking" MUST prevent the merge. Divergences classified as "acceptable" MUST
produce a signed receipt before the merge proceeds.

### INV-CLV-CORPUS
The compatibility corpus MUST be version-controlled, contain at least 1000 test
cases, and accept community contributions via a documented pull-request
workflow. Every corpus update emits CLV-004.

## Acceptance Criteria

1. Lockstep comparison runs on every CI push (INV-CLV-CONTINUOUS).
2. Compatibility corpus pass rate >= 95% (INV-CLV-COVERAGE).
3. Per-test divergence detection completes in < 100 ms (target metric).
4. Zero blocking regressions merge without a gate failure (INV-CLV-REGRESSION).
5. Corpus is version-controlled with >= 1000 test cases (INV-CLV-CORPUS).
6. All four event codes (CLV-001 through CLV-004) are emitted at the correct
   lifecycle points.
7. Divergence classification (harmless / acceptable / blocking) is applied to
   every detected divergence.
8. Per-API-family compatibility scores are published after each run.

## Dependencies

- Section 10.2 (Compatibility Core) for the API surface enumeration.
- Section 10.13 (FCP Deep-Mined) for connector behavioral baselines.
- CI infrastructure capable of running three runtimes in parallel.

## Verification

Verified by `scripts/check_lockstep_validation.py --json`. Evidence artifacts
are stored in `artifacts/section_13/bd-1w78/`.
