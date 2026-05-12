# bd-23x2 Verification Summary

**Section:** 10.11
**Verdict:** PASS
**Completion-debt bead:** bd-23x2.1

## Scope Delivered

bd-23x2 replaced anti-entropy proof-shape acceptance with canonical MMR-backed
reconciliation verification in
`crates/franken-node/src/runtime/anti_entropy.rs`.

bd-23x2.1 records the missing completion-debt proof surfaces:

- `scripts/check_anti_entropy_reconciliation.py`
- `tests/test_check_anti_entropy_reconciliation.py`
- `tests/e2e/anti_entropy_operator_suite.sh`
- `artifacts/replacement_gap/bd-23x2/operator_e2e_log.jsonl`
- `artifacts/replacement_gap/bd-23x2/operator_e2e_summary.json`
- `artifacts/replacement_gap/bd-23x2/operator_e2e_summary.md`
- `artifacts/replacement_gap/bd-23x2/divergence_fixture_index.json`
- `tests/conformance/mmr_proof_verification.rs`
- `tests/integration/marker_divergence_detection.rs`
- `crates/franken-node/tests/e2e_mmr_proofs_lifecycle.rs`
- `crates/franken-node/tests/e2e_marker_stream_lifecycle.rs`

## Completion-Debt Coverage

- `tests.unit.primary`: covered by the static checker, checker regression
  tests, and the inline Rust anti-entropy unit tests.
- `tests.integration.primary`: covered by cargo-visible MMR conformance,
  marker divergence integration, MMR lifecycle, and marker-stream lifecycle
  suites.
- `tests.e2e.primary`: covered by the operator shell harness that runs the
  anti-entropy checker and emits structured partition/proof/certificate/
  reconvergence evidence artifacts.

## Verification Status

- `python3 scripts/check_anti_entropy_reconciliation.py --json` passes and
  emits the `bd-23x2.1` completion-debt contract.
- `python3 scripts/check_anti_entropy_reconciliation.py --self-test` passes.
- `python3 -m pytest -q tests/test_check_anti_entropy_reconciliation.py`
  passes with regression coverage for missing completion-debt spec items and
  evidence paths.
- `tests/e2e/anti_entropy_operator_suite.sh` passes and emits
  `ANTI_ENTROPY_PARTITION_*`, `ANTI_ENTROPY_PROOF_*`,
  `ANTI_ENTROPY_CERTIFICATE_*`, and `ANTI_ENTROPY_RECONVERGENCE_*` events.
- Fresh cargo-heavy reproof remains gated by current `cargo|rustc`
  contention and must use `rch exec --`.

## Acceptance Coverage Already Proven

- Anti-entropy record admission delegates to canonical
  `mmr_proofs::verify_inclusion`.
- The marker hash used for proof verification is computed from
  `TrustRecord::digest()` rather than trusted from caller input.
- Future-epoch records fail closed without local state mutation.
- Forked histories produce explicit fork detection before reconciliation.
- Sparse-delta reconciliation is bounded by `max_delta_batch`.
- Operator artifacts capture required telemetry fields: `trace_id`, `peer_id`,
  `epoch`, `root_digest`, `delta_mode`, `proof_mode`, `decision`,
  `reason_code`, and `certificate_id`.
