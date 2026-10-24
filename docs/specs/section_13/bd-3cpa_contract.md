# bd-3cpa Contract: >=10x Compromise Reduction Gate

## Goal

Enforce a concrete release gate proving host-compromise reduction of `>= 10x`
for hardened `franken_node` versus an unhardened baseline under the same
reproducible adversarial campaign.

**Current evidence scope (2026-10-24):** the retained v2 fixture and the older
20/2 summary do not qualify a current release. The existing checker now
cryptographically verifies the v2 fixture under an independently pinned public
test key, rejects ambiguous/oversized input, and reports
`evidence_class=historical_fixture_conformance`, `release_qualified=false`.
The test seed is public conformance material, never production measurement
authority. Report aggregation alone is labeled `unverified_report_aggregation`.
This scope correction preserves every release invariant below; current signed
campaign/source/binary/corpus qualification and the real measurement remain
open under `bd-reality-20260923-26n9r.20` and its companion `.21`.

The historical consumer requires Python's `cryptography` Ed25519 runtime,
failing closed if it is unavailable. The signed v2 payload is compact UTF-8
JSON in its retained serde struct-field order, with `signature` removed;
reordering keys changes that signed representation. Its declared SHA-256 and
Ed25519 signature must both verify. The public verification key is pinned by
the consumer, never selected from the artifact. JSON readers reject duplicate
members (including escaped aliases), invalid UTF-8/non-finite numbers, inputs
larger than 64 MiB and nesting deeper than 128 values. No frozen artifact is
regenerated to satisfy this check.

The paired old/new gate check retains the five original control inputs:

| Control | Original gate | Signature-aware historical checker |
|---|---|---|
| Genuine frozen artifact | PASS 27/27 | PASS 27/27, not release-qualified |
| Missing signature | PASS 27/27 | FAIL 26/27 |
| Invalid signature | PASS 27/27 | FAIL 26/27 |
| Substituted embedded public key | PASS 27/27 | FAIL 26/27 |
| Changed signed timestamp | PASS 27/27 | FAIL 26/27 |

Thus this bounded five-input population has one retained acceptance, four
new refusals, no newly admitted input and no denominator/threshold change.
This comparison is verifier conformance, not a new security measurement.

## Quantified Invariants

- `INV-CRG-RATIO`: `compromise_reduction_ratio >= 10.0`, where
  `compromise_reduction_ratio = baseline_compromised / hardened_compromised`.
- `INV-CRG-VECTORS`: Campaign contains at least `20` distinct attack vectors.
- `INV-CRG-CLASS-COVERAGE`: Campaign includes required classes:
  - `rce_dependency`
  - `prototype_pollution`
  - `path_traversal`
  - `ssrf`
  - `deserialization`
  - `supply_chain_injection`
  - `privilege_escalation`
  - `sandbox_escape`
  - `memory_corruption`
  - `command_injection`
- `INV-CRG-IDENTICAL-CAMPAIGN`: Baseline and hardened outcomes are recorded for
  every attack vector in the same campaign runbook.
- `INV-CRG-EQUAL-ATTEMPTS`: `baseline_attempts` MUST equal `franken_attempts`
  (and the cited measured artifact must match). A 10× ratio computed from
  fewer franken-node attempts than baseline attempts is fail-closed.
- `INV-CRG-CONTAINMENT`: At least `3` attack vectors must be marked as
  containment outcomes (`contained`) in hardened mode.
- `INV-CRG-DOC`: Every vector documents attack description, baseline outcome,
  hardened outcome, mitigation, and replay command.
- `INV-CRG-DETERMINISM`: Reordering attack vector entries does not change the
  computed compromise counts, ratio, or verdict.

## Required Data Contract

`artifacts/13/compromise_reduction_report.json` must include:

- Metadata:
  - `bead_id`
  - `generated_at_utc`
  - `trace_id`
  - `campaign_name`
  - `campaign_version`
  - `reproducible_command`
- Aggregate metrics:
  - `minimum_required_ratio`
  - `baseline_compromised`
  - `hardened_compromised`
  - `compromise_reduction_ratio`
  - `total_attack_vectors`
  - `containment_vectors`
- Benchmark proof (`benchmark_proof`) directly citing the measured raw-runtime
  benchmark:
  - `rust_test` =
    `compromise_reduction_v2_measures_raw_runtime_baseline_against_strict_policy`
  - `rust_test_path` =
    `crates/franken-node/tests/compromise_reduction_baseline_bench.rs`
  - `measured_artifact` =
    `artifacts/adversarial/compromise_reduction_v2.json`
  - `expected_min_ratio`
  - `measured_ratio`
  - `baseline_compromised`
  - `franken_compromised`
  - `baseline_attempts`
  - `franken_attempts`
  - `raw_baseline_runtimes`
  - `fail_closed_baseline_unavailable`
  - `proof_assertions`
- Attack vectors (`attack_vectors[]`) with required fields:
  - `attack_id`
  - `attack_class`
  - `attack_description`
  - `baseline_outcome` (`compromised` or `blocked`)
  - `franken_node_outcome` (`compromised`, `blocked`, or `contained`)
  - `mitigation`
  - `script_command`
  - `containment_demonstrated` (boolean)

## Determinism and Adversarial Checks

- Gate must recompute all aggregate metrics from `attack_vectors[]` and verify
  they match declared report values.
- Gate must validate order-invariant computation by repeating checks on a
  reordered vector list.
- Gate must run an adversarial perturbation check by increasing hardened
  compromises and confirming the ratio can flip below threshold.
- Gate must validate that `benchmark_proof` points at the raw-runtime Rust
  benchmark, that the cited artifact exists, and that source assertions prove
  the benchmark fails closed when raw baseline runtimes are unavailable.

## Required Scenarios

1. **Pass scenario**: >=20 vectors, required class coverage, >=3 containment
   vectors, ratio >=10.0.
2. **Threshold-fail scenario**: hardened compromises increase enough to drop
   ratio below 10.0.
3. **Coverage-fail scenario**: attack vectors <20 or required classes missing.
4. **Containment-fail scenario**: containment vectors <3.
5. **Determinism scenario**: shuffled attack list yields identical verdict.
6. **Unequal-attempts fail**: `baseline_attempts != franken_attempts` (the
   2026-02 v2 measurement of 20 vs 10 is this failure mode).

## Structured Event Codes

- `CRG-001`: Compromise metrics computed.
- `CRG-002`: Compromise reduction gate passed (all invariants, including `>= 10x` and equal attempts).
- `CRG-003`: Compromise reduction gate failed (`< 10x`, unequal attempts, or any other fail-closed check).
- `CRG-004`: Attack vector coverage violation.
- `CRG-005`: Containment requirement violation.
- `CRG-006`: Determinism validation executed.
- `CRG-007`: Adversarial perturbation validation executed.

All events include stable `trace_id`.

## Gate Decision Flow

1. Load and validate `compromise_reduction_report.json`.
2. Validate attack vector schema, required class coverage, and vector count.
3. Recompute baseline/hardened compromises and reduction ratio.
4. Verify containment vector threshold (`>=3`).
5. Validate the direct benchmark proof citation and measured artifact.
6. Validate determinism under reordered vector list.
7. Run adversarial perturbation check.
8. Emit structured events and pass/fail verdict.
