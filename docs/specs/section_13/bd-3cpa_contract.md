# bd-3cpa Contract: >=10x Compromise Reduction Gate

## Goal

Enforce a concrete release gate proving host-compromise reduction of `>= 10x`
for hardened `franken_node` versus an unhardened baseline under the same
reproducible adversarial campaign.

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

## Structured Event Codes

- `CRG-001`: Compromise metrics computed.
- `CRG-002`: Compromise reduction gate passed (`>= 10x`).
- `CRG-003`: Compromise reduction gate failed (`< 10x`).
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
