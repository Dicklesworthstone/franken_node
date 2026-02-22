# bd-1nl1 Verification Summary

- Status: **PASS**
- Checker: `31/31` PASS (`artifacts/section_10_17/bd-1nl1/check_report.json`)
- Checker self-test: PASS (`artifacts/section_10_17/bd-1nl1/check_self_test.txt`)
- Unit tests: `8` tests PASS (`artifacts/section_10_17/bd-1nl1/unit_tests.txt`)

## Delivered Surface

- `docs/specs/proof_carrying_speculation.md`
- `crates/franken-node/src/runtime/speculation/mod.rs`
- `crates/franken-node/src/runtime/speculation/proof_executor.rs`
- `tests/conformance/proof_speculation_guards.rs`
- `scripts/check_proof_carrying_speculation.py`
- `tests/test_check_proof_carrying_speculation.py`
- `artifacts/10.17/speculation_proof_report.json`
- `artifacts/section_10_17/bd-1nl1/verification_evidence.json`
- `artifacts/section_10_17/bd-1nl1/verification_summary.md`

## Acceptance Coverage

- Speculation does not activate without proof receipt.
- Activation is restricted to approved `franken_engine` interfaces.
- Guard rejection/failure degrades to deterministic safe baseline.
- Runtime module includes guard + fallback behavior with inline Rust unit tests.
- Machine-readable report captures stable event/error codes and invariants.

## Cargo Quality Gates (`rch`)

- `cargo fmt --check` -> exit `1` (`artifacts/section_10_17/bd-1nl1/rch_cargo_fmt_check.log`)
- `cargo check --all-targets` -> exit `0` (`artifacts/section_10_17/bd-1nl1/rch_cargo_check_all_targets.log`)
- `cargo clippy --all-targets -- -D warnings` -> exit `101` (`artifacts/section_10_17/bd-1nl1/rch_cargo_clippy_all_targets.log`)

`fmt`/`clippy` failures are existing workspace baseline debt outside this bead scope.
