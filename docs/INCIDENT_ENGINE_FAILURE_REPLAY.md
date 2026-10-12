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

This is a library capture API. The native-session transport currently accepts
only completed or uncaught-exception captures. `from_failed_execution` retains
that exception-only contract, so existing `run --capture-replay` callers do not
silently produce a terminal state their receiver rejects. Automatic CLI capture
of engine stops requires the dispatcher to select `from_finalized_failure` and
explicitly admit `EngineFailure` on its authenticated failed-response path.
This change does not claim that integration is present.

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
capability must be recognized. Replay still removes module-loading authority;
it therefore refuses a claimed module denial if the original package was
granted module loading. Module-source capture is not implemented by this API.

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
`Debug` view does not encrypt their contents. Existing completed and guest-
exception v2 payload encodings remain unchanged; older readers reject the new
terminal-state variant rather than treating it as successful execution.

## Native regression tests

The `engine_failure_` tests use the real orchestrator and bounded filesystem
provider, then replay with the original source/data moved away. They cover
denial and budget stops after actual file effects, exact cause/diagnostic
comparison, a changed terminal state, transcript corruption, incomplete cleanup,
wrong traces, unsupported errors and preflight limits. They do not substitute a
Node process for the native engine.

```bash
rch exec -- cargo test -p frankenengine-node engine_failure_
rch exec -- cargo test -p frankenengine-node native_replay::
```

These commands require the supported Rust toolchain and sibling engine checkout.
