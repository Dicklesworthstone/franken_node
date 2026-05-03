# bd-12n3 Verification Summary

## Result
CONTRACT GATES PASS; remote Cargo proof is blocked by a sibling dependency compile error.

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
- `python3 -m pytest -q tests/test_check_idempotency_key_derivation.py` -> PASS (`7 passed`).
- `rustfmt --edition 2024 sdk/verifier/src/bundle.rs sdk/verifier/src/capsule.rs sdk/verifier/src/lib.rs` -> PASS.
- `git diff --check -- sdk/verifier/src/bundle.rs sdk/verifier/src/capsule.rs sdk/verifier/src/lib.rs` -> PASS.
- `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_node_pane11 cargo check -p frankenengine-node --all-targets` -> `101`, blocked in sibling `sqlmodel-frankensqlite`.
- `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_node_pane11 cargo clippy -p frankenengine-node --all-targets -- -D warnings` -> `101`, after verifier SDK clippy blockers were removed, blocked in sibling `sqlmodel-frankensqlite`.
- `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_node_pane11 cargo test -p frankenengine-node idempotency -- --nocapture` -> `101`, blocked before test execution in sibling `sqlmodel-frankensqlite`.
- `python3 scripts/check_section_10_14_gate.py --json` -> PASS (`98.08%` coverage, one remaining failing bead: bd-12n3).

## Remaining Blocker
Remote Cargo cannot complete until `/dp/sqlmodel_rust/crates/sqlmodel-frankensqlite/src/connection.rs:79` stops calling `fsqlite::Connection::open_with_page_size`, which is absent from `fsqlite-core 0.1.2`.
