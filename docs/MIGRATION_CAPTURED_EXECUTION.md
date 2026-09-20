# Captured migration test execution

`scripts/migration_validation_runner.py` now reads the same v1 test-manifest
shape used by native migration validation. It reads the manifest from the
bounded input capture, not from a source tree that may change during execution.

```json
{
  "schema_version": "franken-node/migration-tests/v1",
  "tests": ["packages/api/check.cjs"],
  "execution": {
    "packages/api/check.cjs": {
      "cwd": "packages/api",
      "stdin": "fixtures/request.bin",
      "environment": {
        "NODE_ENV": "test",
        "APP_MODE": "migration",
        "OPTIONAL_TOKEN": null
      }
    }
  }
}
```

Save this file at `.franken-node/migration-tests.json` in each measured project.
Test and input paths are canonical, project-relative paths. The example runs
`check.cjs` inside a fresh captured `packages/api` directory, supplies the exact
captured bytes of `fixtures/request.bin`, and removes `OPTIONAL_TOKEN` from that
test's environment. Each test and each runtime receive independent workspaces
and environment dictionaries. Filesystem comparison remains relative to the
whole workspace, not the selected working directory.

Only standalone JS/TS entrypoints are selected. The manifest does not execute
shell commands, package-manager scripts, installation hooks, or runtime options.
Application argv is not supported by this v1 implementation: unknown settings,
including `args` and `arguments`, fail closed. Native `run` needs additional
CLI-to-engine plumbing before that feature can be exposed safely.

## Running a comparison

```sh
python3 scripts/migration_validation_runner.py ./original \
  --migrated-project ./candidate \
  --compare-filesystem --json --out ./migration-result.json
```

The default commands remain Node and `franken-node run --console-only`. Explicit
`--baseline-command` and `--migration-command` JSON arrays select other trusted
executables; each requires exactly one standalone `{test}` argument. The runner
does not change native security policy or grant capabilities to make a test pass.
It removes inherited `FRANKEN_NODE_ALLOW_DEGRADED_RUNTIME_FALLBACK` and
`FRANKEN_NODE_MIGRATION_FAILURE_DIR` from both guest environments.

Without a manifest, conventional `.test`/`.spec` files and files under `test` or
`__tests__` are discovered, including `.js`, `.mjs`, `.cjs`, `.ts`, `.mts`, and
`.cts`. Dependencies, VCS metadata, migration backups, and runtime state are not
test inventories. An empty implicit suite remains `NO_TESTS`; an invalid or empty
explicit manifest is an error, not permission to fall back to heuristic tests.

## Input and evidence boundaries

The original and candidate must select identical tests and identical execution
settings. Configured stdin bytes must also match, even when the input path is
unchanged. All of these checks happen before resolving or launching runtimes.
Candidate source rewrites are allowed; changing the test request is not.

The manifest is limited to 64 KiB and 1,024 tests. Stdin is limited to 1 MiB and is
written concurrently with draining stdout and stderr under the same process
budget. A test that never reads stdin cannot block the runner indefinitely. At
most 64 application environment overrides are accepted, each value at most
4,096 UTF-8 bytes and all names/values together at most 16 KiB. Runtime, dynamic
loader, and operator-control environment variables cannot be overridden by a
manifest. NUL values and duplicate JSON keys are rejected.

Explicit entrypoints, input files, and working directories must be ordinary
captured objects, not symlinks. Project capture retains its existing rules for
other contained symlinks. Hard-linked regular files are refused because copying
them as independent files would change alias semantics. Distinct original and
candidate project roots may not be nested.

Reports now include `runtime_identities`, `runtime_identity_scope`, and
`runtime_identity_rechecked`. Selected executable files must be outside both
input projects. Their bounded SHA-256 identities are measured before and after
the suite, even after an execution error. A changed, missing, unreadable, or
unverifiable executable makes the overall verdict `ERROR`; completed per-test
observations remain available for diagnosis. Reports do not contain raw stdin,
environment values, or captured stdout/stderr bytes.

These identities measure the selected file, not the authenticity of a runtime
brand, a shell script's interpreter, or its dynamic libraries. They do not pin
an executable descriptor at launch or detect a replacement restored between the
two measurements. Two roles with the same executable hash are not independent
runtime implementations.

A pass still requires successful exits and exact output bytes, plus equal
persistent workspace deltas when requested. Matching crashes, timeouts, or
truncated output do not pass. This remains a trusted-project process comparison,
not an OS sandbox, release certificate, deterministic ambient-environment replay,
or proof that network and other external effects were equivalent.

## Portable captured evidence

Add `--bundle /outside/the/projects/failure.fnmigration` to preserve the exact
captured inputs and retained stdout/stderr, instead of discarding them when the
temporary workspaces close. This is opt-in for both successful and failed runs:

```sh
python3 scripts/migration_validation_runner.py original \
  --migrated-project candidate --compare-filesystem \
  --bundle failure.fnmigration --out validation.json --json
```

The destination must be a new file, outside both projects, in an existing
directory. Publication is private (`0600`), fsynced, atomic and no-clobber. A
concurrent creator is not overwritten. Failure to publish changes the overall
verdict to `ERROR`, while retaining completed test observations.

The stored ZIP contains `manifest.json` and deduplicated `objects/<sha256>`
members. The manifest preserves both source snapshots, file/directory modes,
contained links, runtime identities, execution settings, comparison limits,
per-test effective-environment hashes and the actual report. Binary stdin is
part of the captured project. Raw retained outputs are separate hash-addressed
objects; overflow and timeout outputs retain their incomplete metadata. The
report's `replay_bundle.sha256` measures the complete published archive.

Limits are 512 MiB per archive, 16 MiB per manifest and 60,000 unique objects,
in addition to the existing project and per-stream limits. Bundles contain raw
project files and may contain credentials or other sensitive data from those
files, explicit manifest settings, or program output. Inherited environment
values and executable binaries are not exported. Review the contents before
sharing. SHA-256 detects changes relative to a trusted digest; it is not a
signature, authenticity proof, or proof of equivalent external side effects.

## Verified inspection and real re-execution

Inspection validates the archive, object hashes, captured paths, contained
symlink graph, snapshot digests and stream accounting. It does not stage files,
execute commands, import project code, or print raw captured output:

```sh
python3 scripts/migration_validation_runner.py \
  --inspect-bundle failure.fnmigration --json
```

Re-execution requires a trusted **external** digest from the original report,
plus both commands explicitly supplied by the operator. Commands stored inside
the archive are never implicitly executed. The executable location may change,
but its bytes and permission mode must match; arguments after the executable
must be identical to the recorded command.

```sh
DIGEST=$(python3 -c 'import json; print(json.load(open("validation.json"))["replay_bundle"]["sha256"])')
python3 scripts/migration_validation_runner.py \
  --replay-bundle failure.fnmigration --expected-bundle-sha256 "$DIGEST" \
  --baseline-command '["node", "{test}"]' \
  --migration-command '["franken-node", "run", "--console-only", "{test}"]' \
  --out replay.json --json
```

The command above matches a capture made with the default runtime templates.
For a capture made with custom commands, supply those same argument arrays.
Both projects, dependencies, binary stdin and per-test settings are reconstructed
from the verified archive in new private temporary workspaces. The original
project directories are not read and need not exist. Original limits, band and
filesystem comparison mode are reused, not silently overridden.

Before the first guest launch, the recovered input identities, selected runtime
measurements and effective per-test environment hashes must all match. Restore
the original application environment before replay; inherited values are not
available from the archive. There is no option to waive mismatches and still
call the result a reproduction. The existing before/after runtime checks also
apply to the re-executed suite.

Results separate reproduction from compatibility:

| Replay outcome | CLI exit | Meaning |
| --- | --- | --- |
| `REPRODUCED` | 0 | Actual process outcomes, exact stream hashes/counts/completeness, and requested workspace deltas match. |
| `CHANGED` | 1 | The verified inputs ran, but the observed behavior changed. |
| `ERROR` | 2 | Verification, identity/environment admission, or execution infrastructure failed. |

The original `PASS`/`FAIL` compatibility result and the new
`execution.summary.verdict` remain separate. Reproducing a nonzero exit does
**not** convert a compatibility failure into success. Timing measurements and
relocated temporary paths in report metadata are excluded from comparison;
paths printed by a guest remain literal output and are **not** normalized.
Incomplete/error suites are inspectable but cannot earn `REPRODUCED`.

Re-execution is real execution of trusted project code, not a sandbox. The
archive does not contain external services, absolute-path files, system time,
entropy, dynamic libraries or a script runtime's interpreter. Those differences
can produce `CHANGED` even when captured inputs and executable files match.
Network and other external effects can occur again. This feature does not
claim deterministic ambient-effect replay or native Node/Franken parity.

The reader rejects compressed/duplicate/unknown archive members, unsafe paths,
symlink escapes/cycles, children beneath links, missing objects and inconsistent
summary/output accounting before execution. It bounds ZIP directory allocation
before invoking the ZIP parser, and never uses archive extraction helpers.
Archive validation is not publisher authentication: obtain the expected digest
from a source trusted independently of the bundle.

## Cancellation and partial evidence

The standalone runner owns SIGINT/SIGTERM for the duration of a CLI invocation.
The first signal is latched rather than raised inside process launch, pipe
handling, or cleanup. No later test or candidate leg is started after a
cancellation request. The current process group is killed, its direct child is
reaped, and already-written stdout/stderr receive a bounded best-effort drain.
Repeated signals do not interrupt this cleanup or change first-signal attribution.

A cancelled invocation exits 130 for SIGINT or 143 for SIGTERM. Its overall
verdict is `ERROR`, with `cancellation.signal` and an `ExecutionCancelled` error;
completed observations are not discarded. An interrupted process is marked
`termination: "cancelled"`, with incomplete streams. An earlier timeout or output
limit remains the recorded process cause if it preceded cancellation. With
`--bundle`, capture still attempts to publish the input snapshots and retained
partial output. With `--out`, the CLI still attempts to publish the JSON report.
Disk or publication failures remain errors; no artifact durability is promised
when publication itself fails. A signal arriving after an archive has already
been serialized does not rewrite that immutable archive: it can describe the
completed execution while the outer invocation reports interruption.

Interrupted bundles can be inspected, but cannot be certified as `REPRODUCED`.
Cancellation during `--replay-bundle` also returns `ERROR`, retains partial
execution diagnostics, and leaves the original bundle unchanged. Pre-cancelled
library calls launch nothing. Libraries may supply a per-call
`CancellationState`; only the CLI installs signal handlers, and restores them
when it returns. Independent library invocations do not share cancellation state.

This is POSIX process-group supervision, not hostile-code containment. It does
not claim termination of descendants that deliberately escape the group, reap
non-child processes, handle SIGKILL/power loss, or bound uninterruptible kernel
I/O. The post-termination drain is limited to 250 milliseconds and the configured
stream byte bound; incomplete streams never become successful comparisons.
