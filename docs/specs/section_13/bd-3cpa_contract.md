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
The CLI now defaults to current v3 qualification, refusing absent campaign,
independent context or authority inputs. Inspect the retained fixture explicitly
with `--historical-conformance`; this inspection cannot qualify a release.
This preserves every release invariant below. The current statement verifier
has protocol tests, while real current-source measurement, producer integration
and independent acceptance remain open under `bd-reality-20260923-26n9r.20`
and its companion `.21`. Synthetic verifier positives are not experiments.

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

## Current v3 signed campaign statement

The default command requires all three independent inputs:

```bash
python3 scripts/check_compromise_reduction_gate.py --json \
  --campaign /evidence/current-campaign.json \
  --expected-context /trusted/frozen-candidate-context.json \
  --trusted-measurement-key-hex "$MEASUREMENT_AUTHORITY_PUBLIC_KEY_HEX"
```

Missing inputs fail with `CURRENT_MEASUREMENT_INPUTS_REQUIRED`. The explicit
inspection modes `--historical-conformance`, `--replay-campaign` and
`--self-test` cannot silently ignore current campaign inputs. No default
measurement key or producer-selected context is trusted. The v2 public fixture
key and the two well-known RFC8032 public test keys cannot qualify v3 authority.
Other trust provenance remains the caller's responsibility: cryptographic
possession alone does not prove that an experiment occurred.

The statement has exactly `schema_version`, `campaign_id`, `generated_at_utc`,
`context`, `cases`, `summary` and `signature`. The schema is
`franken-node/compromise-campaign/v3`. All declared statement content is covered
by the independent verifier's canonicalization; unsupported fields, floats, duplicate
JSON members and invalid Unicode are refused. A positive frame authenticates
a measurement statement under the caller's authority; it is not external
reproduction or qualification of the entire franken_node release.

The independently supplied `context` has exactly:

- `source_revisions`: five full lowercase Git revisions for `franken_node`,
  `franken_engine`, `fastapi_rust`, `frankentui`, `sqlmodel_rust`.
- `source_selection`: the exact RCH compile-source identity
  `<node-revision>-overlay-<64-hex-fingerprint>`, including immutable selections.
  Its revision must match `source_revisions.franken_node`.
- `binary_sha256`: distinct `sha256:<64 lowercase hex>` identities for `node`,
  `bun`, `native`; aliases or one runtime reused as its incumbent are refused.
- `runtime_versions`: the actual nonempty version strings for those runtimes.
- `corpus_sha256`: the independently frozen fixture-inventory commitment.
- `policy_profile`: `strict`, and `policy_sha256` for the exact policy input.

The complete context must match the caller's separate frozen context. Freshness
requires timezone-aware timestamps, no future date, and age at most 86,400
seconds. `--max-age-seconds` may require a shorter interval; zero, booleans or a
larger interval cannot widen the gate.

Each case has exactly `case_id`, `attack_class`, `template_sha256`,
`observations`. IDs are distinct bounded ASCII identifiers. The corpus hash is
SHA256 of `franken-node:compromise-campaign-corpus:v3:` followed by canonical
JSON for the inventory sorted by `case_id`, each entry containing precisely
`case_id`, `attack_class`, `template_sha256`. The external expected digest
prevents dropping, replacing or relabeling cases without detection. At least
20 cases and all ten classes remain mandatory.

`observations` contains exactly one `node`, `bun`, `native` record per case.
The common record fields are `available`, `binary_sha256`, `input_sha256`,
`stdout`, `stderr`, `exit_code`, `timed_out`, `control_executed`, `compromised`.
All actual binary identities must match the frozen context. A positive control
is independently derived from the exact line `FN_CONTROL:<case_id>` in guest
stdout; source strings, error excerpts and containing substrings do not count.
Both raw incumbents must execute that control and trip their host-compromise
oracle. A raw process stopped after its real control and compromise is retained
as a baseline loss, with `timed_out=true`/`exit_code=null`; this never supplies
a successful defense. Missing runtimes, incomplete raw controls, native
timeouts and harness failures cannot reduce the denominator or score a win.

Native records also contain `outcome`, `evidence`, `security_control`,
`contained`. Typed security controls distinguish capability, SSRF, IFC and
ambient-authority lowering refusals from unsupported/harness failures. The
runtime-containment count requires both `contained=true` and an actually
executed guest control. A lowering refusal is preventive evidence and cannot
supply any of the three required executed containment outcomes. Compromises
remain in the signed census and are never filtered out.

The verifier independently derives and exactly compares the integer summary:
`baseline_attempts`, `franken_attempts`, `baseline_compromised`,
`franken_compromised`, `executed_containment`, `prevented_before_control`,
`ratio_numerator`, `ratio_denominator`, `minimum_required_ratio`.
Attempts equal the full case count, the conservative point ratio is
`baseline_compromised / max(franken_compromised,1)`, and the threshold remains
10. No boolean-as-integer or producer-declared count override is accepted.
Zero observed native compromises also has an infinite empirical ratio; this
does not establish zero population risk. Separate descriptive Wilson95% rate
intervals are recomputed from the same census, without introducing a new
confidence threshold. One/two real losses out of20 are retained and can meet
20x/10x respectively; three losses fail the unchanged 10x criterion.

The unsigned statement is sorted-key, compact UTF-8 JSON with integer-only
numbers and `signature` omitted. Its signature object contains exactly
`algorithm=ed25519`, `public_key_hex`, `statement_sha256`, `signature_hex`.
The digest is `sha256:` plus SHA256 of the canonical unsigned bytes. Ed25519
signs `franken-node:compromise-campaign-signature:v3:` followed by the unsigned
byte length as an eight-byte little-endian integer, then those bytes. Public
key equality to the independently supplied authority is mandatory. The
signature itself is exactly 64 bytes, lowercase hex encoded.

Results use `franken-node/compromise-campaign-verification/v1`, including
stable errors, independently computed counts, evidence class and explicit
`independently_reproduced=false`. Passing current qualification means the
externally pinned, fresh statement satisfies this campaign contract. It does
not manufacture the real run, operator authority, production adoption or the
independent replications still required elsewhere in the charter.

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

## Current producer execution

The existing Rust benchmark's measured entry point selects v3 only when
`FRANKEN_NODE_CAMPAIGN_VERSION=3` is explicitly set. It then requires
`FRANKEN_NODE_CAMPAIGN_CONTEXT`, `FRANKEN_NODE_CAMPAIGN_TRUSTED_KEY_HEX`,
`FRANKEN_NODE_CAMPAIGN_KEY_FILE`, `FRANKEN_NODE_CAMPAIGN_WORK_DIR` and
`FRANKEN_NODE_CAMPAIGN_OUTPUT`. The key file contains a raw 32-byte seed from
the external authority; it is never printed or bundled. There is no generated
or embedded authority fallback. Work and output paths must be new; existing
historical evidence is never replaced. The mode records observations, including
losses and invalid outcomes; successful producer exit asserts no security ratio.

The context must match the exact compiled `RCH_BUILD_SOURCE`, the compiled
`CARGO_BIN_EXE_franken-node`, actual Node/Bun hashes and versions, the frozen
fixture descriptors and strict policy bytes. Each descriptor binds the case,
package/version, class, vector, oracle and attack template. These hashes can be
inspected with the `current_campaign_canonical_bytes_and_frozen_inventory` test;
its output is labeled `source_inventory_only`, never measurement evidence.

Each case executes exactly once in Node, Bun and native strict mode. Linux
`bwrap` isolates the PID/mount namespaces, clears inherited environment and
exposes only public runtime files and that leg's owned project, oracle and
state directories. The measurement key must be outside these mounts. Real
loopback oracles remain reachable equally for all three runtimes. Raw streams,
rendered inputs and observations are retained per leg. Native control output
comes only from structured guest buffers, never an error's embedded source.
The producer currently classifies executed typed-denial receipts, compromise,
and completed uncompromised execution; it conservatively leaves unsupported,
unrecognized prevention and startup failures invalid. Adding a prevention
classification cannot supply any required executed containment.

The unselected legacy mode retains its historical conformance behavior. The
current release verifier will not accept its public-key v2 result. Neither
mode has yet supplied the independently authorized fresh v3 campaign required
to close `.20` or its acceptance companion `.21`.

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
