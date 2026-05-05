# bd-12n3 Verification Summary

## Result
CONTRACT GATES PASS; bd-177e4 remains blocked by current all-target clippy warning debt and missing refreshed persisted pass logs for the cargo check/focused-test proofs.

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
- `RCH_REQUIRE_REMOTE=1 ... cargo +nightly-2026-02-19 check -p frankenengine-node --all-targets` -> PASS recorded in the bd-177e4 Beads thread at 2026-05-05 16:04 UTC: `[RCH] remote vmi1293453 (803.3s)`. The persisted artifact log is still the old 2026-05-03 dependency failure and needs refresh before closeout.
- `RCH_REQUIRE_REMOTE=1 ... cargo +nightly-2026-02-19 clippy -p frankenengine-node --all-targets -- -D warnings` -> `101`, refreshed by PinkFern on 2026-05-05. The stale `sqlmodel-frankensqlite` blocker is gone; clippy reaches `frankenengine-node` on remote `ts2` and fails with 187 warning-as-error errors across current all-target warning debt.
- `RCH_REQUIRE_REMOTE=1 ... cargo +nightly-2026-02-19 test -p frankenengine-node --features extended-surfaces --test idempotency_key_derivation -- --nocapture` -> PASS recorded in the bd-177e4 Beads thread at 2026-05-05 16:04 UTC: 6/6 passed on `vmi1293453`. The persisted artifact log is still the old 2026-05-03 dependency failure and needs refresh before closeout.
- `python3 scripts/check_section_10_14_gate.py --json` -> PASS (`98.08%` coverage, one remaining failing bead: bd-12n3).

## Remaining Blocker
Remote Cargo is no longer blocked by `/dp/sqlmodel_rust/crates/sqlmodel-frankensqlite/src/connection.rs:79`. The current blocker is broad `cargo clippy -p frankenengine-node --all-targets -- -D warnings` debt: the refreshed RCH log reaches `frankenengine-node` and fails with 187 warning-as-error errors. The first blockers are in `engine_dispatcher.rs`, `rollout_state.rs`, `divergence_gate.rs`, `fleet_transport.rs`, `evidence_ledger.rs`, `remote_cap.rs`, `threshold_sig.rs`, `cli.rs`, and `config.rs`.
