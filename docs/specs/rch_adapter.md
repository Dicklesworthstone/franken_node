# RCH Adapter Classification Contract

**Bead:** bd-lozra
**Schema:** `franken-node/rch-adapter/outcome/v1`

## Purpose

The RCH adapter classifies `rch exec -- ...` validation results before they are
used as Beads, doctor, or validation-broker evidence. It prevents worker
timeouts, missing toolchains, local fallback, filesystem pressure, and cargo
contention from being reported as product failures or green proof.

## Command Policy

The adapter accepts only explicit cargo validation commands:

- `cargo build`
- `cargo check`
- `cargo clippy`
- `cargo test`
- `cargo fmt`

The command may be wrapped in `env KEY=VALUE ... cargo ...`. `CARGO_TARGET_DIR`
is parsed from either the wrapper or the invocation environment. Remote proof
requires `RCH_REQUIRE_REMOTE=1` or `RCH_REQUIRE_REMOTE=true`.

The default policy allows only `-p frankenengine-node` validation. Commands that
target a different package, omit the cargo action, use shell wrappers, or lack
the remote requirement fail closed with `broker_internal_error`.

## Outcome Classes

| Class | Meaning | Product failure | Retryable |
|-------|---------|-----------------|-----------|
| `passed` | Remote RCH command exited zero with a remote marker | No | No |
| `command_failed` | Non-zero exit without a narrower classifier | Yes | No |
| `compile_failed` | Cargo reached compilation and emitted Rust compile errors | Yes | No |
| `test_failed` | Cargo test reached execution and reported failing tests | Yes | No |
| `worker_timeout` | RCH/SSH timed out, including `[RCH-E104]` | No | Yes |
| `worker_missing_toolchain` | Worker lacks the requested Rust toolchain | No | Yes |
| `worker_filesystem_error` | Worker disk/permission/tempdir state blocked validation | No | Yes |
| `local_fallback_refused` | Remote proof was required but execution fell back locally | No | Yes |
| `contention_deferred` | Active cargo/rustc count exceeded policy threshold | No | Yes |
| `broker_internal_error` | Adapter policy rejected the command | No | No |

## Green Proof Rule

An adapter result is green only when all of these are true:

- `outcome == "passed"`
- `execution_mode == "remote"`
- `product_failure == false`

An exit code of zero without a remote RCH marker is not green when remote proof
is required.

## Required Output Fields

Every classification emits:

- `schema_version`
- `command_digest`
- `action`
- `package`
- `outcome`
- `execution_mode`
- `worker_id`
- `timeout_class`
- `exit_code`
- `retryable`
- `product_failure`
- `reason_code`
- `detail`
- `stdout_digest`
- `stderr_digest`
- `duration_ms`

The stdout and stderr digests are SHA-256 over full output plus bounded snippets
for human triage. Future validation-broker receipts can embed these fields or
map them into the broker receipt schema without reading Agent Mail history.

## Flight Recorder Mapping

The validation flight recorder contract in
`docs/specs/validation_flight_recorder.md` consumes `RchAdapterOutcome` as the
authoritative output classification for one attempt. The recorder may add
timeline, target-dir, broker/coalescer, and recovery-plan context, but it must
not weaken this adapter contract:

- green proof still requires `outcome=passed`, `execution_mode=remote`, and
  `product_failure=false`;
- `[RCH-E104] SSH command timed out (no local fallback)` remains
  `worker_timeout` with `ssh_command`;
- local fallback refusal, missing toolchain, worker filesystem pressure, and
  contention deferral remain retryable infrastructure outcomes, not product
  failures;
- compile and test failures remain product failures, not retryable worker
  infrastructure.

## Fixture Coverage

The Rust tests cover deterministic fixtures for:

- `[RCH] remote <worker> (...)` success and worker extraction.
- `[RCH-E104] SSH command timed out (no local fallback)`.
- Worker missing requested Rust toolchain.
- Worker filesystem pressure such as `No space left on device`.
- `CARGO_TARGET_DIR` parsing from an `env` command wrapper.
- Local fallback refusal with exit code zero.
- Contention deferral before product-output classification.
- Compile and test failure separation.
