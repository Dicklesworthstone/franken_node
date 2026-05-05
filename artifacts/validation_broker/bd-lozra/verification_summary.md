# bd-lozra Verification Summary

## Result

RCH adapter implementation is present with deterministic fixture coverage and a
scoped strict-remote RCH proof. The default-feature proof timed out in the
remote worker layer before tests executed; the adapter classifies that failure
as worker timeout / retryable infrastructure, not as product failure.

## Delivered

- `crates/franken-node/src/ops/rch_adapter.rs`
- `crates/franken-node/tests/rch_adapter_classification.rs`
- `docs/specs/rch_adapter.md`
- `artifacts/validation_broker/bd-lozra/rch_adapter_fixtures.v1.json`
- `crates/franken-node/src/ops/mod.rs` export for `ops::rch_adapter`

## Covered Classifications

- `passed`
- `command_failed`
- `compile_failed`
- `test_failed`
- `worker_timeout`
- `worker_missing_toolchain`
- `worker_filesystem_error`
- `local_fallback_refused`
- `contention_deferred`
- `broker_internal_error`

## Source Checks

- `rustup run nightly-2026-02-19 rustfmt --edition 2024 --check crates/franken-node/src/ops/mod.rs crates/franken-node/src/ops/rch_adapter.rs crates/franken-node/tests/rch_adapter_classification.rs` -> PASS.
- `python3 -m json.tool artifacts/validation_broker/bd-lozra/rch_adapter_fixtures.v1.json` -> PASS.
- `git diff --check -- crates/franken-node/src/ops/mod.rs crates/franken-node/src/ops/rch_adapter.rs crates/franken-node/tests/rch_adapter_classification.rs docs/specs/rch_adapter.md crates/franken-node/Cargo.toml artifacts/validation_broker/bd-lozra/rch_adapter_fixtures.v1.json artifacts/validation_broker/bd-lozra/verification_summary.md` -> PASS.
- `UBS_SKIP_RUST_BUILD=1 ubs crates/franken-node/src/ops/mod.rs crates/franken-node/src/ops/rch_adapter.rs crates/franken-node/tests/rch_adapter_classification.rs` -> PASS with 0 critical issues.

## RCH Proof

Default-feature strict-remote proof was attempted first:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PRIORITY=low RCH_TEST_TIMEOUT_SEC=1800 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=2400 rch exec -- env CARGO_TARGET_DIR=/data/tmp/franken_node-rusticplateau-bd-lozra-target CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo +nightly-2026-02-19 test -p frankenengine-node --test rch_adapter_classification -- --nocapture
```

Result: worker timeout before test execution on `vmi1153651`:

```text
[RCH] remote vmi1153651 failed [RCH-E104] SSH command timed out (no local fallback)
```

This is classified by the adapter as `worker_timeout`, `timeout_class =
ssh_command`, `retryable = true`, `product_failure = false`.

Scoped strict-remote proof avoided the unrelated default-feature sibling-engine
compile path and exercised the exported production module:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PRIORITY=low RCH_TEST_TIMEOUT_SEC=900 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1500 rch exec -- env CARGO_TARGET_DIR=/data/tmp/franken_node-rusticplateau-bd-lozra-scoped-target CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo +nightly-2026-02-19 test -p frankenengine-node --no-default-features --features http-client,external-commands --test rch_adapter_classification -- --nocapture
```

Result: PASS on `ts2`, 6 tests passed, `[RCH] remote ts2 (462.0s)`.
