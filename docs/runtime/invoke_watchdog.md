# Runtime invocation watchdog

`runtime_invoke_watchdog.py` is an opt-in external supervisor for the native
`franken-node runtime invoke` command. Unlike a cooperative engine execution
budget, its wall-clock deadline can stop an engine that never returns.

```sh
python3 scripts/runtime_invoke_watchdog.py \
  --franken-node-bin target/debug/franken-node \
  --artifacts-dir /tmp/franken-invoke-001 \
  --wall-time-ms 5000 \
  --kill-grace-ms 250 \
  -- example.js --execution-budget-ms 1000 --execution-budget-ticks 1000
```

The artifact directory must be new. The supervisor refuses to reuse it, so a
failed launch cannot accidentally inherit evidence from an earlier successful
run. It owns the native `--output-dir`; do not supply that flag after `--`.
`--cwd` changes the native process working directory. Relative binary paths and
artifact paths are resolved before changing that directory. Argument boundaries
are preserved; commands are never interpreted by a shell.

The default wall deadline is 30 seconds, independently of native execution
budgets. Both time arguments accept positive whole milliseconds, up to one day.
Cleanup has its own termination grace period and bounded leader-reaping wait, so
elapsed time may exceed the execution deadline by cleanup and scheduling time.
This is not a real-time scheduling guarantee.

## Evidence and exit semantics

Every run records `watchdog.json`, raw `stdout.log` and `stderr.log`, and the
native receipt location `runtime/`. Native receipts are neither rewritten nor
fabricated when an engine hangs. `watchdog.json` starts in a fail-closed `running`
state, is updated with the native PID after launch, and is replaced atomically at
completion. A nonterminal receipt is never evidence of success. If storage is
unavailable, the wrapper fails and stops its native process rather than
continuing without evidence.

| `outcome` | Meaning | Wrapper exit |
| --- | --- | --- |
| `completed` | Native process exited zero; inspect native receipts for workload semantics. | 0 |
| `runtime_failed` | Native process failed or was signalled; not inferred to be a wrapper timeout. | Native exit, or 128 + signal |
| `wrapper_timeout` | The external supervisor observed its own deadline expire. | 124 |
| `cancelled` | Supervisor received SIGINT or SIGTERM and stopped the invocation. | 128 + first cancellation signal |
| `spawn_error` | Native process could not be launched. | 125 |
| `supervisor_error` / `cleanup_failed` | Evidence or cleanup could not complete normally. | 125 |

Only an actual supervisor deadline sets `wrapper_deadline_exceeded: true` and
`timeout_layer: "wrapper"`. Native exit 124 remains `runtime_failed`, not
`wrapper_timeout`. Likewise, a native engine/kernel budget error is preserved as
native evidence, not relabelled based on its stderr text. If timeout termination
makes the engine exit zero, the wrapper still fails with `wrapper_timeout`.
Cancellation cannot overwrite an already observed deadline or cleanup failure.

Events carry monotonic elapsed milliseconds. The receipt records the exact
argument vector, working directory, runtime exit status, output byte counts,
artifact locations, and TERM/KILL cleanup actions. It does not copy environment
variables. Arguments and runtime output may themselves contain sensitive values;
keep the private artifact directory appropriately protected.

## Scope and limits

This supervisor requires POSIX process groups. It terminates the invocation's
process group, including descendants that outlive the leader or ignore TERM,
and escalates to KILL after the grace period. Repeated SIGINT/SIGTERM signals do
not interrupt that cleanup or receipt publication.

It is a liveness supervisor, **not a security sandbox**: a deliberately detached
child that creates a new session can escape the group. SIGKILL directed at the
supervisor cannot be handled; host-level process containment is still needed for
that failure mode. Raw streams go directly to files, avoiding pipe deadlocks and
unbounded supervisor memory, but this version does not impose a disk-output
quota. Native receipts may be absent or partial after an interrupted invocation.

Direct `franken-node runtime invoke` calls are unchanged and are **not** protected
unless launched through this supervisor. This implements the external watchdog
portion of bead `bd-xzig5`; native CLI flag integration remains separate work.

## Regression tests

```sh
python3 -m unittest discover -s tests -p 'test_runtime_invoke_watchdog.py' -v
```

Tests use real OS subprocesses and a fake native CLI, including hangs, crashes,
large binary output, exit-code provenance, cancelled launches, repeated signals,
partial evidence, receipt-write failures and orphaned descendants. They do not
require Rust or the sibling engine checkout, and do not substitute for an actual
FrankenEngine integration run. Two process-state assertions require Linux procfs;
the remaining process-group tests run on POSIX.
