# bd-12n3 Verification Summary

## Result
CONTRACT GATES PASS; persisted RCH check, clippy, and focused idempotency proofs are fresh and passing.

## Delivered
- `crates/franken-node/src/remote/idempotency.rs`
- `crates/franken-node/src/remote/mod.rs` (`pub mod idempotency;`)
- `tests/conformance/idempotency_key_derivation.rs`
- `scripts/check_idempotency_key_derivation.py`
- `tests/test_check_idempotency_key_derivation.py`
- `artifacts/10.14/idempotency_vectors.json`
- `docs/specs/section_10_14/bd-12n3_contract.md`
- `sdk/verifier/src/bundle.rs`
- `sdk/verifier/src/capsule.rs`
- `sdk/verifier/src/lib.rs`
- `artifacts/section_10_14/bd-12n3/check_report_idempotency_key_derivation.json`
- `artifacts/section_10_14/bd-12n3/check_idempotency_key_derivation_self_test.log`
- `artifacts/section_10_14/bd-12n3/pytest_check_idempotency_key_derivation.log`
- `artifacts/section_10_14/bd-12n3/rch_cargo_check_all_targets.log`
- `artifacts/section_10_14/bd-12n3/rch_cargo_clippy_all_targets.log`
- `artifacts/section_10_14/bd-12n3/rch_cargo_test_idempotency_key_derivation.log`
- `artifacts/section_10_14/bd-12n3/check_section_10_14_gate.json`
- `artifacts/section_10_14/bd-12n3/verification_evidence.json`

## Gate Results
- `python3 scripts/check_idempotency_key_derivation.py --json` -> PASS (`30/30` checks).
- `python3 scripts/check_idempotency_key_derivation.py --self-test` -> PASS.
- `python3 -m pytest -q tests/test_check_idempotency_key_derivation.py` -> PASS (`9 passed`).
- `rustfmt --edition 2024 sdk/verifier/src/bundle.rs sdk/verifier/src/capsule.rs sdk/verifier/src/lib.rs` -> PASS.
- `git diff --check -- sdk/verifier/src/bundle.rs sdk/verifier/src/capsule.rs sdk/verifier/src/lib.rs` -> PASS.
- `RCH_REQUIRE_REMOTE=1 ... cargo +nightly-2026-02-19 check -p frankenengine-node --all-targets` -> PASS, refreshed by PinkFern on 2026-05-06 from `/data/projects/franken_node`: `[RCH] remote vmi1156319 (1712.3s)`.
- `RCH_REQUIRE_REMOTE=1 ... cargo +nightly-2026-02-19 clippy -p frankenengine-node --all-targets -- -D warnings` -> PASS, refreshed by PinkFern on 2026-05-06 from `/data/projects/franken_node_pinkfern_clean_bd_empw2`: `[RCH] remote vmi1156319 (1649.0s)`.
- `RCH_REQUIRE_REMOTE=1 ... cargo +nightly-2026-02-19 test -p frankenengine-node --features extended-surfaces --test idempotency_key_derivation -- --nocapture` -> PASS, refreshed by PinkFern on 2026-05-06 from `/data/projects/franken_node`: `[RCH] remote vmi1156319 (3213.7s)`, 6/6 passed.
- `python3 scripts/check_section_10_14_gate.py --json` -> PASS (`100.0%` coverage, `0` failing beads).

## Remaining Blocker
None. The persisted artifact logs now show exit 0 for all-target check, all-target clippy, and the focused idempotency conformance target.
