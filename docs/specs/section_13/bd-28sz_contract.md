# bd-28sz Contract: >=95% Compatibility Corpus Pass Gate

## Goal

Enforce a hard release gate requiring compatibility corpus pass performance at or above program targets, with deterministic measurement, per-band and per-family floors, regression detection, and reproducible evidence.

## Quantified Invariants

- `INV-CCG-OVERALL`: Aggregate corpus pass rate is `>= 95%` for release eligibility.
- `INV-CCG-BAND`: Band thresholds are met on every run: `core >= 99%`, `high-value >= 95%`, `edge >= 90%`.
- `INV-CCG-FAMILY-FLOOR`: No API family pass rate falls below `80%`.
- `INV-CCG-CORPUS-SIZE`: Targeted corpus includes `>= 500` test cases.
- `INV-CCG-TRACKING`: Every failing test is mapped to an investigation bead with explicit status.
- `INV-CCG-REPRODUCIBILITY`: Corpus results are versioned and reproducible for the same `corpus_version` and `franken_node_version`.
- `INV-CCG-RATCHET`: Decrease versus previous release corpus pass rate is treated as regression and escalated.
- `INV-CCG-PROVENANCE` (bd-ihusm): The corpus must attest a genuine measurement via `corpus.provenance`. Only `"lockstep-oracle-run"` is accepted by the release gate; any other value (for example `"authored-fixture-expectations"`) or an absent field is refused fail-closed, so synthesized or hand-authored results can never satisfy the L1 pass-rate leg.
- `INV-CCG-DIGEST-BINDING` (bd-ihusm): `corpus.result_digest` MUST recompute from `per_test_results` under the canonical `ccg_corpus_result_digest_v1` scheme (domain-separated, field-separated, sorted). A fabricated or silently-edited digest fails both the Python CI gate and the Rust close-condition L1 leg, and the declared `totals` are re-derived from `per_test_results` rather than trusted as-is.

## Required Data Contract

`artifacts/13/compatibility_corpus_results.json` must include:

- Corpus metadata: `corpus_version`, `franken_node_version`, `lockstep_oracle_version`, `result_digest`.
- Aggregate metrics: totals, passes, failures, pass percentage.
- Band breakdown: `core`, `high-value`, `edge`.
- API-family breakdown for Node.js families:
  `fs`, `http`, `net`, `crypto`, `stream`, `buffer`, `path`, `os`, `child_process`,
  `cluster`, `events`, `timers`, `url`, `querystring`, `zlib`, `tls`.
- Per-test records with at least: `test_id`, `api_family`, `band`, `risk_band`, `status`.
- Failing-test investigation mapping: `test_id -> bead_id + investigation_status`.
- CI gate decision metadata including threshold/rachet evaluation.

## Determinism Requirements

- Re-running verification on identical artifact input yields identical aggregate metrics and verdict.
- Reordering `per_test_results` does not change computed pass rates or gate outcome.
- Adversarial perturbation (drop pass rate below 95%) deterministically flips release decision to blocked.

## Required Scenarios

1. Scenario A: Corpus includes a new deep coverage expansion and pass-rate computation updates deterministically.
2. Scenario B: Run with aggregate pass rate above 95% and band/family floors met -> release allowed.
3. Scenario C: Simulate aggregate pass rate below 95% -> release blocked with threshold breach event.
4. Scenario D: Compare against previous release where current pass rate drops -> regression detected and escalated.

## Structured Event Codes

- `CCG-001`: Corpus pass-rate computed.
- `CCG-002`: Threshold met and release allowed.
- `CCG-003`: Threshold breached and release blocked.
- `CCG-004`: Regression detected versus previous release.

All events must include stable `trace_id`, `corpus_version`, and release candidate context.

## Machine-Readable Artifacts

- `artifacts/13/compatibility_corpus_results.json`
- `artifacts/section_13/bd-28sz/verification_evidence.json`
- `artifacts/section_13/bd-28sz/verification_summary.md`

## Gate Tiers

The aggregate pass_rate determines the release gate tier:

| Tier | Pass Rate Range | Release Decision | Severity         |
|------|-----------------|------------------|------------------|
| G0   | < 80%           | Blocked          | Critical         |
| G1   | 80-89%          | Blocked          | Needs work       |
| G2   | 90-94%          | Blocked          | Near threshold   |
| G3   | 95-99%          | Allowed          | Passing          |
| G4   | 100%            | Allowed          | All tests passing|

Only tiers G3 and G4 allow a release. Tiers G0 through G2 block the release.

## Thresholds

| Threshold              | Value       | Rationale                                     |
|------------------------|-------------|-----------------------------------------------|
| Aggregate pass rate    | >= 95%      | Minimum acceptable compatibility coverage     |
| Per-module floor       | >= 80%      | No module may be severely incompatible        |
| Regression tolerance   | 0%          | Strict ratchet prevents backsliding           |
| Maximum corpus run time| <= 30 min   | Ensures CI feedback loop stays fast           |

## Corpus Result Schema

A corpus run result is a JSON object with the following required fields:

| Field             | Type     | Description                                   |
|-------------------|----------|-----------------------------------------------|
| `run_id`          | string   | Unique identifier for the corpus run          |
| `timestamp`       | string   | ISO 8601 UTC timestamp of run completion      |
| `total_tests`     | integer  | Total number of tests in the corpus           |
| `passed_tests`    | integer  | Number of tests that passed                   |
| `failed_tests`    | integer  | Number of tests that failed                   |
| `skipped_tests`   | integer  | Number of tests that were skipped             |
| `errored_tests`   | integer  | Number of tests with infrastructure errors    |
| `aggregate_rate`  | float    | Aggregate pass rate as a percentage           |
| `module_results`  | list     | Per-module breakdown (see below)              |
| `duration_seconds`| float    | Wall-clock time for the full run              |

### Module Result Sub-Schema

| Field           | Type    | Description                               |
|-----------------|---------|-------------------------------------------|
| `module_name`   | string  | Name of the compatibility module          |
| `total`         | integer | Total tests in this module                |
| `passed`        | integer | Passed tests in this module               |
| `failed`        | integer | Failed tests in this module               |
| `pass_rate`     | float   | Module-level pass rate as a percentage    |

## Gate Decision Flow

1. Execute full compatibility corpus
2. Compute aggregate and per-module pass rates
3. Check INV-CCG-OVERALL (aggregate >= 95%)
4. Check INV-CCG-FAMILY-FLOOR (all modules >= 80%)
5. Check INV-CCG-RATCHET (no regression from previous run)
6. Check INV-CCG-REPRODUCIBILITY (all evidence fields present)
7. Emit CCG-001 (run completed)
8. If all checks pass: emit CCG-002, allow release
9. If any check fails: emit CCG-003 (and CCG-004 if regression), block release

## Acceptance Mapping

- `>= 500` tests and required family coverage satisfy corpus completeness.
- Per-test tagging (`api_family`, `risk_band`) and band thresholds satisfy quality instrumentation.
- Aggregate and per-family checks enforce release safety.
- Failing-test bead linkage enforces actionable follow-up.
- Reproducibility metadata and digest enforce independent verification.
