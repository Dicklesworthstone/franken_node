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
  --max-output-bytes 16777216 \
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

## Captured binary stdin

`--stdin-file request.bin` supplies an explicit binary request instead of the
default `/dev/null`. `--max-stdin-bytes` bounds the source (16 MiB by default;
1 byte through 1 GiB accepted). Empty files are valid. Source loading happens
before changing the child's working directory and before the invocation budget
starts. It requires a regular file, rejects a symlink at the supplied file path,
and uses nonblocking, no-follow opening plus before/after identity checks to
reject ordinary concurrent replacement or mutation. FIFOs, devices, directories,
and oversized sources are rejected before an invocation is launched. This is not
a guarantee against a hostile filesystem server or blocking filesystem I/O.

The exact immutable request is saved as private `stdin.bin` (mode `0600`) and
flushed before launch; the receipt records its byte length and SHA-256 digest.
Failure to retain that snapshot prevents execution. Replacing the original file
after capture cannot substitute the bytes subsequently delivered to the guest.
An execution budget exhausted during snapshot persistence also prevents launch.

Input is fed through a nonblocking **pipe**, not a regular-file descriptor, while
both output streams are drained. Large requests cannot deadlock a guest that
writes output before reading input. The supervisor closes the pipe to deliver
EOF after the last byte, and stops further input delivery before termination
cleanup on timeout, cancellation, or output-limit failure.

`stdin_captured`, `stdin_delivered_bytes`, `stdin_delivery_state`, and
`stdin_delivery_complete` separate preserved input from transport progress.
Delivered means accepted into the OS pipe, **not proven consumed by the guest**.
When a guest exits zero before the whole supplied request is queued, the strict
supervisor result is `input_incomplete`; the original zero exit is retained in
`runtime_exit_code`. Native nonzero exits, timeout, and cancellation keep their
own outcome even when delivery is partial. A program intentionally accepting
only a request prefix should be given that prefix as its explicit input.

For another run with the captured request, pass the previous `stdin.bin` as
`--stdin-file` and choose a new artifact directory. The digest is input identity,
not authentication or a claim of deterministic ambient-effect replay. Input may
contain credentials or other sensitive data; protect and retain the artifact
directory accordingly. Library callers use immutable `stdin_data: bytes` and
`max_stdin_bytes`; omitting `stdin_data` preserves the original null-input mode.

## Bounded output capture

`--max-output-bytes` caps each captured stream independently (16 MiB by default;
1 byte through 1 GiB accepted). There is no unlimited setting. Exactly the limit
is allowed; observing another byte stops the invocation with an output-limit
failure. Each log retains the exact binary prefix, never more than its limit.

The supervisor multiplexes nonblocking stdout and stderr pipes with bounded,
fair reads. Neither a flood nor a descendant retaining a pipe disables the
wall deadline or cancellation. Pipes continue draining during TERM/KILL cleanup
without increasing retained files beyond their limits. Buffered overflow found
after the leader exits zero still invalidates success. An inherited pipe that
never reaches EOF within bounded cleanup produces `output_incomplete`, not an
unbounded wait or an apparently complete successful invocation.

Receipts distinguish retained `stdout_bytes` / `stderr_bytes` from
`stdout_observed_bytes` / `stderr_observed_bytes` actually read from pipes.
Observed counts are not estimates of all bytes generated by a terminated guest.
Per-stream `*_eof` and `*_complete`, `output_complete`, and
`output_limit_streams` describe evidence completeness. Complete stream capture
alone does not establish workload success or native receipt validity. An earlier
timeout or cancellation remains the primary outcome even if cleanup also
observes excessive output.

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
| `completed` | Native process exited zero with complete captured streams and supplied input queued; inspect native receipts for workload semantics. | 0 |
| `runtime_failed` | Native process failed or was signalled; not inferred to be a wrapper timeout. | Native exit, or 128 + signal |
| `wrapper_timeout` | The external supervisor observed its own deadline expire. | 124 |
| `cancelled` | Supervisor received SIGINT or SIGTERM and stopped the invocation. | 128 + first cancellation signal |
| `output_limit_exceeded` | At least one captured stream exceeded its byte limit. | 125 |
| `output_incomplete` | Pipe EOF could not be established during bounded cleanup. | 125 |
| `input_incomplete` | Native process exited zero before the complete captured request was queued. | 125 |
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
that failure mode. The output quota bounds writes by the supervisor to its two
captured logs, not arbitrary guest filesystem writes or the native receipt
directory. Untrusted guests still require filesystem/process isolation. Native
receipts may be absent or partial after an interrupted invocation.

Direct `franken-node runtime invoke` calls are unchanged and are **not** protected
unless launched through this supervisor. This implements the external watchdog
portion of bead `bd-xzig5`; native CLI flag integration remains separate work.

## Regression tests

```sh
python3 -m unittest discover -s tests -p 'test_runtime_invoke_watchdog.py' -v
```

Tests use real OS subprocesses and a fake native CLI, including hangs, crashes,
large binary output, exact quota boundaries, post-exit overflow, failed capture,
exit-code provenance, cancelled launches, repeated signals, partial evidence,
receipt-write failures and orphaned or detached pipe holders. They do not require
Rust or the sibling engine checkout. Input tests cover exact binary bytes,
backpressure, early closure, non-reading guests, cancellation, file replacement,
capture failures, and CLI wiring. An additional real Node stdin oracle runs when
`node` is available; it does not substitute for an actual FrankenEngine
integration run. Two process-state assertions require Linux procfs; the remaining
process-group tests run on POSIX.
