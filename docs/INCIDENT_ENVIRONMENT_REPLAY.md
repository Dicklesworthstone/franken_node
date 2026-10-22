# Native incident replay of explicit environment reads

Native replay accepts `EnvRead` only as an explicitly declared runtime
capability. It consumes the exact typed environment requests and outcomes
already recorded by the engine. It does not inspect the replay machine's
process environment, install an environment provider for replay, or infer
values from the operator's current configuration.

A producer must supply the original execution with the engine's bounded
`EnvironmentSnapshotHostIo`, or a product-authorized composition containing it,
and an ordinary host-I/O recorder. The existing `NativeReplayCapture::from_execution`
and `NativeReplayCapture::from_failed_execution` entrypoints retain the observed
results. This change does not introduce a new CLI environment-loading option.

Only names actually read enter the host-effect transcript. An absent variable
(`None`) differs from a present empty variable (`Some("")`). Presence tests,
repeated reads and Unicode values retain those distinctions. Exact request
order and complete transcript consumption remain mandatory. Reads interleaved
with other host effects stay in the existing host-I/O transcript or, for
process-authorized runs, the existing global effect journal. No map lookup or
name-based deduplication replaces that ordered evidence.

Before constructing a replay engine, environment entries are checked for the
explicit capability, valid names, engine-defined value limits and matching
request/response kinds. Recorded errors remain errors. Missing, reordered or
unused entries cannot be replaced with current environment values or a guessed
absence. The existing recorder still verifies consumption and finalization.

Environment-derived values retain the engine's Secret information-flow floor.
Replay does not add declassification receipts, relax sink checks, grant raw
`process` or `process.env` object access, or authorize environment mutation.
Runtime module loading is still disabled because module sources are not part
of an entry-only capture. An explicitly frozen-module capture can now include
the bounded source capsule and its resolution pins. Replay restores that
closed-world resolver with the original capabilities, without opening the
original project or installing a live module provider. This new source path
is awaiting native qualification in
[the execution TODO](progress/REALITY_CHECK_AND_BRIDGE_PLAN.md#offline-npm-and-native-build-execution--2026-10-22).
Interrupted or unfinalized execution remains unsupported.

The product receipt kind is `env_read` (stable binary tag 8). Receipts commit
to the name and typed result without rendering either private string. The
result commitment distinguishes absence from a present empty value. Explicit
environment reads use the distinct `ifl-src:secret-environment` source label;
they are not relabeled as secret-file reads. The existing bounded receipt
byte-containment tracking is not a complete per-value information-flow proof.
SDK non-exfiltration claims match exact label-set commitments. A policy that
forbids mixed file/environment flows must also disclose the canonical combined
label-set commitment; a single-source commitment does not cover another set.

## Privacy and authentication

Captures can contain secrets in environment outcomes, execution results,
source, arguments and other host effects. The capture's `Debug` output does
not include its payload, but JSON serialization intentionally retains the
original private bytes. Redacting the serialized evidence would change the
execution input and invalidate its commitment. Store and export it as sensitive
data. An integrity digest or signature does not encrypt it.

The envelope digest is not a trust anchor. Authenticate the containing run
record or incident bundle against an independent trusted key before calling
`reexecute`. Execution comparison cannot establish who supplied a self-hashed
capture. The current envelope requires
`franken-node/native-replay-capture/v3`; historical v2 captures are refused,
not reinterpreted as having authenticated newly added module-source fields.
Canonical-payload checks remain mandatory. SDK inspection authenticates and
checks metadata; it does not decode, resolve or execute the module capsule.

## Focused regression coverage

The inline `native_environment_` tests execute the native orchestrator against
explicit, bounded fixture snapshots, then invoke the public native replay path.
They cover values, missing/empty variables, presence, Unicode, repeated reads,
completion and certified exception prefixes, order/exhaustion/suffix failures,
changed values, authority and Secret-flow restrictions. The
`environment_transcript_` and `malformed_environment_` tests exercise preflight
shape checks, engine limits and private-data-free validation diagnostics. The
`replay_capture_debug_` test checks that debug redaction does not alter JSON.

These tests are inline library tests. A default `cargo test` filters them out
at the library gate. Use the dedicated inline configuration from
`.github/workflows/inline-lib-tests-gate.yml` in a complete supported workspace;
the default features include the engine. First require nonzero discovery:

```bash
set -o pipefail
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 RUSTFLAGS="--cfg franken_node_inline_tests" \
  cargo test -p frankenengine-node --lib --features extended-surfaces,test-support \
  ops::native_replay:: -- --list | tee /tmp/franken-node-native-replay.list
python3 scripts/check_inline_lib_tests.py /tmp/franken-node-native-replay.list --min-tests 1 --json

RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 RUSTFLAGS="--cfg franken_node_inline_tests" \
  cargo test -p frankenengine-node --lib --features extended-surfaces,test-support \
  ops::native_replay::
```

Inspect the list for the named environment, transcript, malformed-capture and
debug tests above, and retain the execution summary with nonzero executed tests
and no failures. A passing preflight, an empty filter or skipped-only output
does not verify this behavior. The broader module filter also exercises the
existing completed, exception and engine-stop replay tests. Discovery and
execution still require the normal disk and remote-worker admission checks.

These are implementation tests, not a claim of arbitrary Node compatibility,
complete ambient-environment replay, or qualified multi-file incident replay.
The separate CLI regression
`native_incident_replay_preserves_explicit_environment_reads_and_private_receipts`
uses Cargo's exact built product executable and actual `init`/capture/bundle/
replay commands. Its execution status, and the frozen CJS/ESM regression
status, are tracked in the execution TODO above; their presence is not a pass.
