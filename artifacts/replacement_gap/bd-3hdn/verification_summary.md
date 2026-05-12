# bd-3hdn Verification Summary

**Section:** 10.4
**Verdict:** PASS
**Completion-debt bead:** bd-3hdn.1

## Scope Delivered

bd-3hdn replaced extension-registry shape checks with the canonical signed
manifest admission kernel in
`crates/franken-node/src/supply_chain/extension_registry.rs`.

bd-3hdn.1 records the missing completion-debt proof surfaces:

- `scripts/check_signed_extension_registry.py`
- `tests/test_check_signed_extension_registry.py`
- `tests/e2e/extension_registry_operator_suite.sh`
- `artifacts/replacement_gap/bd-3hdn/operator_e2e_log.jsonl`
- `artifacts/replacement_gap/bd-3hdn/operator_e2e_summary.json`
- `artifacts/replacement_gap/bd-3hdn/operator_e2e_summary.md`
- `artifacts/replacement_gap/bd-3hdn/adversarial_fixture_index.json`
- `artifacts/golden/supply_chain_attestation_manifest.json`

## Completion-Debt Coverage

- `tests.unit.primary`: covered by the static checker, checker regression
  tests, and the inline Rust extension-registry unit tests.
- `tests.integration.primary`: covered by the existing cargo-visible
  conformance, adversarial poisoning, and registry/claims lifecycle suites.
- `tests.e2e.primary`: covered by the operator shell harness that runs the
  signed-extension checker and emits structured evidence artifacts.
- `tests.golden.primary`: covered by the signed extension manifest golden
  artifact and the Rust golden test that rejects placeholder signature
  material.
- `telemetry.primary`: covered by operator JSONL events with `trace_id`,
  `artifact_id`, `publisher_key_id`, `decision`, `reason_code`,
  `transparency_checkpoint`, and `attestation_digest` fields.

## Verification Status

- `python3 scripts/check_signed_extension_registry.py --json` passes and emits
  the `bd-3hdn.1` completion-debt contract with `19 passed, 0 failed`.
- `python3 scripts/check_signed_extension_registry.py --self-test` passes.
- `python3 -m pytest -q tests/test_check_signed_extension_registry.py` passes
  with `26 passed` and regression coverage for missing completion-debt spec
  items and evidence paths.
- `tests/e2e/extension_registry_operator_suite.sh` passes and emits
  `EXT_REG_ADMISSION_*` plus `EXT_REG_PROVENANCE_*` events.
- Existing bd-209w evidence records 42 Rust unit tests for
  `extension_registry.rs`; fresh cargo reproof remains gated by current
  `cargo|rustc` contention and must use `rch exec --`.

## Acceptance Coverage Already Proven

- Extension admission goes through `AdmissionKernel` and
  `artifact_signing::verify_signature` rather than signature shape checks.
- Canonical admission digests bind manifest bytes, publisher key ID,
  provenance commit, build system, and output hash.
- Provenance validation delegates to the canonical attestation-chain verifier.
- Transparency proof verification is fail-closed when required.
- Negative witnesses and audit records link rejection reason codes to operator
  explanations.
- Golden manifest coverage freezes signed extension manifest serialization and
  threshold-signature shape.
