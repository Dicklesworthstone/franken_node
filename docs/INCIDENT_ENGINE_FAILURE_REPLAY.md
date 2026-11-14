# Native replay of finalized engine stops

The public `NativeReplayCapture::from_finalized_failure` entrypoint captures
four independently typed outcomes: an uncaught guest exception, an interpreter
capability denial, exhaustion of the interpreter's instruction budget, or a
console entry/byte budget stop. The existing `reexecute` entrypoint consumes
these captures using the native engine.
It never repeats live filesystem, network, environment or process effects.

## Capture and integration boundary

The producer passes the exact package, runtime/orchestrator settings, ambient
grant, arguments and process-capture provider used in the original run, together
with the live orchestrator and its returned error. Only the typed primary error
selects the stopping reason. Matching words in a guest exception, stderr, exit
code or watchdog receipt cannot manufacture an engine failure.

The run-facing `from_failed_execution` entrypoint now delegates every certified
post-cell failure to `from_finalized_failure`. Existing `run --capture-replay`
callers can therefore retain uncaught guest exceptions, capability denials,
instruction-budget exhaustion, and console-budget stops without inferring a stop
from stderr, an exit code, or a watchdog. The capture and verifier schemas carry
the terminal state
explicitly as `uncaught_exception` or `engine_failure`.

This does not broaden the accepted failure boundary: supervisor deadlines,
external cancellation, panics, interrupted effects, and incomplete cleanup
remain non-replayable.

## Inspecting attempts that never finalized

An engine panic, interrupted supervisor, or failed evidence write can prevent
an attempt from producing a run receipt or replay bundle. Native execution
retains its admission before starting the worker and retains a signed
supervisor outcome before updating the inventory. The incident commands expose
those observations independently of finalized replay captures:

```bash
# Discover retained failures and unresolved sessions in the current project.
franken-node incident list --json

# Authenticate admissions and available supervisor outcomes for this project.
franken-node incident sessions --json

# Inspect one launch from the session_nonce in a run error or incident listing.
franken-node incident sessions --session <UUID> --json

# Retained evidence can be selected after the original source tree is moved.
franken-node incident sessions --project /old/absolute/project --session <UUID> --json

# Export the selected original signatures using the existing forensic format.
franken-node incident capture --from-session <UUID> --out session.fnforensics.json --json
```

`incident sessions` verifies the immutable admission and outcome receipts
against the existing protected local product authority. It checks their
session, project, identity-capture, and admission commitments before returning
authenticated metadata. A signed outcome that survived a failed inventory
update can be recovered for inspection; this query does not repair or rewrite
the database. Missing authority is never created by inspection.

The report separates authenticated records from `source_errors` and identity
captures without authenticated lifecycle evidence. An unverified database
outcome is withheld. Pending admissions retain unknown liveness and effects;
a missing process, elapsed deadline, or absent outcome cannot prove that a
worker stopped. A terminal supervisor observation preserves its specific
outcome, including `panicked`, `interrupted`, and `execution_failed`, along with
the recorded process and host-effect observations. Panic diagnostics and the
bounded parent-observed effect journal remain available when they were signed.

`incident list` includes failures and unresolved observations with
`source = "native_session"` and IDs of the form `native-session:<UUID>`.
Their severity is `unknown`: a failed execution alone does not establish a
security incident. Ordinary fully observed successful sessions remain available
in `incident sessions`. The existing severity filter applies to these entries
too, so `--severity high` does not include entries of unknown severity.
Only authenticated project admissions become native-session incident entries.
The additive `native_session_inspection` JSON field retains source errors and
identity-only captures separately: these can come from shared operator state
without authenticated project attribution. Human output reports their counts
or an inspection error; an unavailable inventory never becomes a project
incident.

These observations are retained local forensic evidence. They do not certify
native replay, external-effect completion, fleet quiescence, or historical
completeness after evidence deletion. Both `replay_certified` and
`quiescence_certified` remain false. Exported replay bundles and the coverage
gate continue to require their existing authenticated execution inputs. See
[the portable forensic protocol](../sdk/verifier/NATIVE_SESSION_FORENSICS.md)
for verification of session exports with an independently supplied product
public key.

## Executing a native counterfactual

The native counterfactual mode executes the captured program with explicitly
removed capabilities. It can reveal the actual console output and terminal
state of that restricted execution, including changed guest control flow:

```bash
franken-node incident counterfactual \
  --bundle incident.fnbundle \
  --model native \
  --deny-capability fs_write,network_egress \
  --trusted-public-key exporter.pub \
  --trusted-run-public-key original-run.pub \
  --trusted-runtime-public-key product-root.pub \
  --timeout-ms 30000 \
  --json
```

The three public-key inputs independently authenticate the export, original
run, and runtime identity/effect ledger. The containing bundle is read once
and authenticated before captured input is executed. The worker first
reproduces the completed original run, including its policy decisions and
frozen module sources. A failed or incomplete baseline refuses the entire
counterfactual.

The second execution preserves the captured source, arguments, ambient
authority, runtime settings and nondeterminism inputs while subtracting the
requested capability tags. It never adds authority or changes an entire
runtime profile. Use repeated `--deny-capability` flags or a comma-separated
list; `--policy` remains the input for the synthetic and production decision
models.

The restricted execution's provider only serves the next exact request from
the authenticated original host-input transcript. An unused suffix is
reported explicitly. A different, reordered or additional request poisons
the attempt, even if the guest catches the error. No live filesystem,
network, environment, entropy or process operation supplies missing data.
Changed branches that require unrecorded results are therefore refused.

Both executions share one supervised Linux worker and one total deadline,
including startup and protocol draining. The worker must terminate and its
response must match the exact request before the parent accepts observations.
Process-authorized captures and removing `module_load` are currently refused;
the latter would remove the authority needed to enter the frozen program.
The engine's intrinsic `vm_dispatch`, `heap_allocate`, and `console`
capabilities cannot be removed through package declarations and are also
refused as restrictions. Captured ambient process-shape authority is preserved.

The `franken-node/incident-native-counterfactual/v1` report binds the original
incident, verified origins, restriction and observed outcome into its digest.
It includes the verified baseline, remaining declared capabilities, actual terminal
state and console, and consumed/unused original input counts. The digest is
an integrity commitment, not a signature. The branch has
`replay_certified = false` and `policy_equivalence_certified = false`; an
observed capability restriction is not a certificate for a different policy
or a rollout approval. Native mode does not support `--promote`.

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

```json
{"kind":"console_budget_exceeded","entries":2,"max_entries":1,"bytes":39,"max_bytes":8388608}
```

The instruction budget must belong to one of the captured execution profiles.
For a console stop, the entry and byte limits must together match an effective
interpreter profile derived from the captured runtime settings. The configured
`max_console_entries` override is retained, and the byte ceiling comes from
the engine's profile. At least one attempted counter must exceed its ceiling;
equal limits do not establish exhaustion. Replay compares both observed
counters and both limits exactly. Console timer/count labels also consume
budgets, so attempted counts must not be inferred from retained output length.

Only accepted console output is retained in the console transcript. A rejected
oversized message is regenerated from the captured source during replay; a
small source that constructs a large message does not put the rejected message
in the capture. Replay still consumes the recorded effect prefix without
repeating live reads or writes.

The denied capability must be recognized. Without an authenticated module-source capsule,
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

The four `engine_failure_console_` tests extend that coverage to both native
execution profiles and both console ceilings. They use an explicit low entry
limit and a generated message larger than the byte limit, check the bounded
accepted-output capture, move original files before replay, and require that
the captured write is not repeated. They also mutate limits, attempted
counters, diagnostics, runtime settings and effect transcripts; a guest throw
imitating the console diagnostic, an unfinalized typed error, a wrong cleanup
trace and an additional cancellation error must not certify the captured
console stop.

These are inline library tests, excluded by the default library test gate.
Use the dedicated discovery and execution commands in
[the environment replay regression instructions](INCIDENT_ENVIRONMENT_REPLAY.md#focused-regression-coverage),
including `--lib`, the inline `RUSTFLAGS` override, full feature selection and
nonzero discovery check. The `ops::native_replay::` filter includes these tests;
confirm the `engine_failure_` names are listed and actually executed. A zero-test
success is not replay proof. This requires the supported Rust toolchain, sibling
engine checkout, disk admission and an available remote worker.
