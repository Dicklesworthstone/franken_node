# Native replay of finalized engine stops

The public `NativeReplayCapture::from_finalized_failure` entrypoint captures
three independently typed outcomes: an uncaught guest exception, an interpreter
capability denial, or exhaustion of the interpreter's instruction budget. The
existing `reexecute` entrypoint consumes these captures using the native engine.
It never repeats live filesystem, network, environment or process effects.

## Capture and integration boundary

The producer passes the exact package, runtime/orchestrator settings, ambient
grant, arguments and process-capture provider used in the original run, together
with the live orchestrator and its returned error. Only the typed primary error
selects the stopping reason. Matching words in a guest exception, stderr, exit
code or watchdog receipt cannot manufacture an engine failure.

The run-facing `from_failed_execution` entrypoint now delegates every certified
post-cell failure to `from_finalized_failure`. Existing `run --capture-replay`
callers can therefore retain uncaught guest exceptions, capability denials, and
instruction-budget exhaustion without inferring a stop from stderr, an exit
code, or a watchdog. The capture and verifier schemas carry the terminal state
explicitly as `uncaught_exception` or `engine_failure`.

This does not broaden the accepted failure boundary: supervisor deadlines,
external cancellation, panics, interrupted effects, and incomplete cleanup
remain non-replayable.

## Required finalization

All supported failures share the existing post-cell certification boundary:
successful cell close, verified cell execution transcript, matching trace and
cell identities, no additional recorder/evidence/containment errors, and a
contiguous fully completed effect journal. A retained console prefix by itself
is insufficient. External cancellation, supervisor timeout, panic, interrupted
effects, shared work-pool authority and incomplete cleanup remain unsupported.

An engine-failure capture uses `expected.terminal_state = "engine_failure"`
and retains a typed reason plus the exact primary interpreter diagnostic:

```json
{"kind":"capability_denied","capability":"env_read"}
```

```json
{"kind":"instruction_budget_exhausted","budget":100000}
```

The budget must belong to one of the captured execution profiles. The denied
capability must be recognized. Without an authenticated module-source capsule,
replay removes module-loading authority and refuses a claimed module denial
if the original package was granted module loading. Explicit frozen-module
capture can now supply its source capsule to this API. In that case replay
validates the capsule and prepared entry binding, then restores only its
closed-world resolver and the original capabilities. No live module reads are
authorized. Native qualification of that new path is still pending in
[the execution TODO](progress/REALITY_CHECK_AND_BRIDGE_PLAN.md#offline-npm-and-native-build-execution--2026-10-22).

## What a match establishes

Engine-stop verdicts use `verification_scope = "engine_failure_prefix"`. A match
requires the same terminal state, typed reason, exact diagnostic, trace identity,
console and finalized ordered effects. Another stop of the same broad class is
not enough. Missing, reordered or unused transcript entries fail certification,
including when execution stops at the same later instruction budget.

Budget diagnostics preserve the engine's own observed work-count text. They
are not a completed IR4 witness, independently finalized instruction count or
complete nondeterminism trace. Those unavailable comparison fields remain
`null`, as do the guest-exception and completed-policy comparisons for an
engine stop. No probability of maliciousness or general runtime equivalence
follows from reproducing this prefix.

The enclosing signed record or bundle must be authenticated against an
independent trust anchor before re-execution. Rehashing a modified payload is
not authentication. Serialized captures may contain private data; the redacted
`Debug` view does not encrypt their contents. The current capture envelope is
`franken-node/native-replay-capture/v3`; historical v2 captures are refused.
The outcome schema remains `franken-node/native-replay-outcome/v2`, with
unavailable comparisons still represented as `null`. A historical signature
does not attest to the new module-source fields.

## Native regression tests

The `engine_failure_` tests use the real orchestrator and bounded filesystem
provider, then replay with the original source/data moved away. They cover
denial and budget stops after actual file effects, exact cause/diagnostic
comparison, a changed terminal state, transcript corruption, incomplete cleanup,
wrong traces, unsupported errors and preflight limits. They do not substitute a
Node process for the native engine.

These are inline library tests, excluded by the default library test gate.
Use the dedicated discovery and execution commands in
[the environment replay regression instructions](INCIDENT_ENVIRONMENT_REPLAY.md#focused-regression-coverage),
including `--lib`, the inline `RUSTFLAGS` override, full feature selection and
nonzero discovery check. The `ops::native_replay::` filter includes these tests;
confirm the `engine_failure_` names are listed and actually executed. A zero-test
success is not replay proof. This requires the supported Rust toolchain, sibling
engine checkout, disk admission and an available remote worker.
