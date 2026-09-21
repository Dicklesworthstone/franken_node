#!/usr/bin/env python3
"""Run the native runtime with an independent, fail-closed wall-clock deadline.

The supervisor is deliberately outside the engine process. Engine execution
budgets remain unchanged; only an observed supervisor deadline is classified as
``wrapper_timeout``. Raw output and native receipts remain separate evidence.

Example:
    python3 scripts/runtime_invoke_watchdog.py --artifacts-dir /tmp/invoke-001 \\
        --wall-time-ms 5000 --franken-node-bin target/debug/franken-node \\
        -- example.js --execution-budget-ms 1000

Requires POSIX process groups. The artifact directory must not already exist.
Exit 124 means a wrapper deadline *or* a forwarded native exit 124; consumers must
read watchdog.json's outcome rather than inferring timeout provenance from an
exit code. Exit 125 indicates a supervisor or launch failure.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, BinaryIO, Iterator, Sequence


SCHEMA = "franken-node.runtime-invoke-watchdog.v1"
DEFAULT_MAX_OUTPUT_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_STDIN_BYTES = 16 * 1024 * 1024
IO_CHUNK_BYTES = 64 * 1024


class Cancellation:
    """Cancellation is latched, never raised asynchronously across Popen()."""

    def __init__(self) -> None:
        self.signum: int | None = None

    def request(self, signum: int) -> None:
        if self.signum is None:
            self.signum = signum


@contextmanager
def cancellation_signals() -> Iterator[Cancellation]:
    """Keep TERM/INT from interrupting scope cleanup or receipt publication.

    Used by the CLI on its main thread, not implicitly by library callers.
    Repeated signals preserve the first cancellation cause.
    """
    cancellation = Cancellation()
    previous = {}
    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            previous[sig] = signal.signal(sig, lambda number, _frame: cancellation.request(number))
        yield cancellation
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def positive_ms(value: str) -> int:
    try:
        number = int(value)
        seconds = number / 1000
    except (ValueError, OverflowError):
        raise argparse.ArgumentTypeError("budget must be a positive integer in milliseconds") from None
    if number <= 0 or not math.isfinite(seconds) or seconds > 86400:
        raise argparse.ArgumentTypeError("budget must be between 1 and 86400000 milliseconds")
    return number


def positive_bytes(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("byte limit must be a positive integer") from None
    if not 1 <= number <= 1024 * 1024 * 1024:
        raise argparse.ArgumentTypeError("byte limit must be between 1 and 1073741824")
    return number


def read_stdin_file(path: Path, limit: int = DEFAULT_MAX_STDIN_BYTES) -> bytes:
    """Capture one bounded regular file, rejecting symlink and nonregular sources.

    The opened descriptor and final path must still identify the same unchanged
    file. The returned immutable bytes, not this path, are used for execution.
    This detects ordinary concurrent changes, not a hostile filesystem server.
    """
    positive_bytes(str(limit))

    def identity(info: os.stat_result) -> tuple[int, ...]:
        return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns)

    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("stdin source must be a regular file, not a symlink or device")
    if before.st_size > limit:
        raise ValueError(f"stdin source exceeds {limit} bytes")
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    with os.fdopen(os.open(path, flags), "rb", buffering=0) as source:
        opened = os.fstat(source.fileno())
        if identity(opened) != identity(before):
            raise ValueError("stdin source changed before capture")
        content = bytearray()
        while True:
            part = source.read(min(IO_CHUNK_BYTES, limit - len(content) + 1))
            if not part:
                break
            content.extend(part)
            if len(content) > limit:
                raise ValueError(f"stdin source exceeds {limit} bytes")
        if (identity(os.fstat(source.fileno())) != identity(opened)
                or identity(path.lstat()) != identity(opened)
                or len(content) != opened.st_size):
            raise ValueError("stdin source changed during capture")
    return bytes(content)


def _write_stdin_snapshot(path: Path, content: bytes) -> None:
    """Retain the complete input before granting a child any execution time."""
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())


class _InputFeed:
    """Bounded nonblocking pipe delivery; bytes queued are not bytes consumed."""

    def __init__(self, content: bytes, selector: selectors.BaseSelector) -> None:
        self.content = memoryview(content)
        self.selector = selector
        self.pipe: BinaryIO | None = None
        self.delivered = 0
        self.state = "not_started"
        self.error: str | None = None

    def attach(self, pipe: BinaryIO | None) -> None:
        if pipe is None:
            raise ValueError("missing stdin pipe")
        self.pipe = pipe
        os.set_blocking(pipe.fileno(), False)
        self.state = "sending"
        if self.content:
            self.selector.register(pipe, selectors.EVENT_WRITE, "stdin")
        else:
            self.stop("delivered")

    def write_ready(self) -> None:
        if self.pipe is None:
            return
        try:
            written = os.write(self.pipe.fileno(),
                               self.content[self.delivered:self.delivered + IO_CHUNK_BYTES])
        except BlockingIOError:
            return
        except BrokenPipeError:
            self.stop("closed_early")
            return
        if written <= 0:
            raise OSError("stdin pipe made no progress")
        self.delivered += written
        if self.delivered == len(self.content):
            self.stop("delivered")

    def stop(self, reason: str = "stopped") -> None:
        if self.pipe is not None:
            try:
                self.selector.unregister(self.pipe)
            except KeyError:
                pass
            self.pipe.close()
            self.pipe = None
            self.state = reason

    def record(self, receipt: dict[str, Any]) -> None:
        receipt["stdin_delivered_bytes"] = self.delivered
        receipt["stdin_delivery_state"] = self.state
        receipt["stdin_delivery_complete"] = self.state == "delivered" and self.error is None
        if self.error is not None:
            receipt["stdin_error"] = self.error


class _OutputCapture:
    """Drain both pipes fairly, retaining only a bounded prefix of each stream.

    EOF is tracked independently of leader exit. Observed counts describe bytes
    actually read, not an estimate of everything a terminated guest generated.
    """

    def __init__(self, stdout: BinaryIO, stderr: BinaryIO, limit: int,
                 stdin_data: bytes | None = None) -> None:
        self.selector = selectors.DefaultSelector()
        self.input = _InputFeed(stdin_data, self.selector) if stdin_data is not None else None
        self.sinks = {"stdout": stdout, "stderr": stderr}
        self.limit = limit
        self.observed = {name: 0 for name in self.sinks}
        self.retained = {name: 0 for name in self.sinks}
        self.eof = {name: False for name in self.sinks}
        self.exceeded: list[str] = []
        self.error: str | None = None
        self.closed = False

    def attach(self, process: subprocess.Popen[bytes]) -> None:
        try:
            for name in self.sinks:
                pipe = getattr(process, name)
                if pipe is None:
                    raise ValueError(f"missing {name} pipe")
                os.set_blocking(pipe.fileno(), False)
                self.selector.register(pipe, selectors.EVENT_READ, name)
            if self.input is not None:
                self.input.attach(process.stdin)
        except BaseException:
            self.close()
            for pipe in (process.stdin, process.stdout, process.stderr):
                if pipe is not None:
                    pipe.close()
            raise

    def pump(self, timeout: float) -> None:
        if self.closed or not self.selector.get_map():
            time.sleep(max(0, timeout))
            return
        name = None
        try:
            # One bounded read per ready stream prevents a stdout flood from
            # starving stderr, deadline checks, or cancellation handling.
            for key, _ in self.selector.select(max(0, timeout)):
                name = key.data
                if name == "stdin":
                    assert self.input is not None
                    self.input.write_ready()
                    continue
                try:
                    data = os.read(key.fd, IO_CHUNK_BYTES)
                except BlockingIOError:
                    continue
                if not data:
                    self.eof[name] = True
                    self.selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                self.observed[name] += len(data)
                remaining = self.limit - self.retained[name]
                if len(data) > remaining and name not in self.exceeded:
                    self.exceeded.append(name)
                pending = memoryview(data)[:remaining]
                while pending:
                    written = self.sinks[name].write(pending)
                    if written is None or written <= 0:
                        raise OSError(f"failed to retain {name} output")
                    self.retained[name] += written
                    pending = pending[written:]
        except (OSError, ValueError) as error:
            if name == "stdin" and self.input is not None:
                self.input.error = f"{type(error).__name__}: {error}"
            else:
                self.error = f"{type(error).__name__}: {error}"
            self.close()
            raise

    def stop_input(self) -> None:
        if self.input is not None:
            self.input.stop()

    def close(self) -> None:
        if not self.closed:
            self.stop_input()
            for key in list(self.selector.get_map().values()):
                self.selector.unregister(key.fileobj)
                key.fileobj.close()
            self.selector.close()
            self.closed = True

    def record(self, receipt: dict[str, Any]) -> None:
        if self.input is not None:
            self.input.record(receipt)
        receipt["output_limit_exceeded"] = bool(self.exceeded)
        receipt["output_limit_streams"] = sorted(self.exceeded)
        for name in self.sinks:
            receipt[f"{name}_observed_bytes"] = self.observed[name]
            receipt[f"{name}_eof"] = self.eof[name]
            receipt[f"{name}_complete"] = (
                self.eof[name] and name not in self.exceeded and self.error is None)
        receipt["output_complete"] = all(receipt[f"{name}_complete"] for name in self.sinks)
        if self.error is not None:
            receipt["output_error"] = self.error


def _write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    """Never expose a partially written or stale success receipt."""
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                     prefix=".watchdog-", delete=False) as handle:
        temporary = Path(handle.name)
        try:
            json.dump(receipt, handle, indent=2, sort_keys=True, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _signal_group(pid: int, sig: int) -> bool:
    try:
        os.killpg(pid, sig)
        return True
    except ProcessLookupError:
        return False


def _stop_process(process: subprocess.Popen[bytes], grace_ms: int,
                  capture: _OutputCapture | None = None) -> dict[str, Any]:
    """Terminate the whole invocation scope, even after its leader exits."""
    cleanup: dict[str, Any] = {"scope": "process_group", "term_sent": False,
                              "kill_sent": False, "leader_reaped": False}
    if capture is not None:
        # Cancellation/timeout begins drain-only cleanup. Never deliver more
        # application input to descendants after the invocation has stopped.
        capture.stop_input()

    def drain_until(deadline: float, *, stop_at_eof: bool = False) -> None:
        while (remaining := deadline - time.monotonic()) > 0:
            if capture is None or capture.closed:
                if not stop_at_eof:
                    time.sleep(remaining)
                return
            if stop_at_eof and all(capture.eof.values()):
                return
            try:
                capture.pump(min(remaining, 0.01))
            except (OSError, ValueError) as error:
                # Failed evidence storage cannot prevent KILL and reaping.
                cleanup["output_error"] = str(error)

    cleanup["term_sent"] = _signal_group(process.pid, signal.SIGTERM)
    # Do not equate the leader exiting with all descendants exiting. A child may
    # ignore TERM, or may inherit output handles after the leader has finished.
    if cleanup["term_sent"]:
        drain_until(time.monotonic() + grace_ms / 1000)
        cleanup["kill_sent"] = _signal_group(process.pid, signal.SIGKILL)
    try:
        process.wait(timeout=max(grace_ms / 1000, 0.1))
        cleanup["leader_reaped"] = True
    except subprocess.TimeoutExpired:
        cleanup["error"] = "process did not exit after SIGKILL"
    # Drain the finite pipe tail after exit, but never wait indefinitely for a
    # detached descendant holding a writer. Such evidence is explicitly partial.
    drain_until(time.monotonic() + max(grace_ms / 1000, 0.1), stop_at_eof=True)
    return cleanup


def supervise(command: Sequence[str], artifacts_dir: Path, *, wall_time_ms: int = 30000,
              kill_grace_ms: int = 250, cwd: Path | None = None,
              max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
              stdin_data: bytes | None = None,
              max_stdin_bytes: int = DEFAULT_MAX_STDIN_BYTES,
              cancellation: Cancellation | None = None) -> dict[str, Any]:
    """Supervise a native invocation. Never parse logs to guess timeout origin.

    The command is an argument vector, not a shell command. The output directory
    is exclusive so a failed launch cannot reuse a previous run's success files.
    No environment variables are copied into the receipt.
    """
    cancellation = cancellation or Cancellation()
    positive_ms(str(wall_time_ms))
    positive_ms(str(kill_grace_ms))
    positive_bytes(str(max_output_bytes))
    positive_bytes(str(max_stdin_bytes))
    if stdin_data is not None and not isinstance(stdin_data, bytes):
        raise ValueError("stdin_data must be immutable bytes or None")
    if stdin_data is not None and len(stdin_data) > max_stdin_bytes:
        raise ValueError(f"stdin data exceeds {max_stdin_bytes} bytes")
    if os.name != "posix":
        raise ValueError("watchdog requires POSIX process-group termination")
    if isinstance(command, (str, bytes)) or not command or any(
            not isinstance(arg, str) or "\x00" in arg for arg in command):
        raise ValueError("command must be a nonempty sequence of NUL-free strings")
    if not command[0]:
        raise ValueError("executable must not be empty")
    artifacts_dir = artifacts_dir.resolve()
    artifacts_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    receipt_path = artifacts_dir / "watchdog.json"
    started = time.monotonic()
    receipt: dict[str, Any] = {
        "schema_version": SCHEMA, "command": list(command),
        "cwd": str((cwd or Path.cwd()).resolve()), "outcome": "running",
        "fail_closed": True, "wrapper_exit_code": 125, "runtime_exit_code": None,
        "wrapper_deadline_exceeded": False, "timeout_layer": None,
        "wall_time_ms": wall_time_ms, "kill_grace_ms": kill_grace_ms,
        "max_output_bytes_per_stream": max_output_bytes,
        "output_limit_exceeded": False, "output_limit_streams": [],
        "output_complete": False,
        "stdin_mode": "null" if stdin_data is None else "pipe",
        "stdin_path": None if stdin_data is None else str(artifacts_dir / "stdin.bin"),
        "stdin_bytes": 0 if stdin_data is None else len(stdin_data),
        "stdin_sha256": None if stdin_data is None else hashlib.sha256(stdin_data).hexdigest(),
        "max_stdin_bytes": max_stdin_bytes, "stdin_captured": False,
        "stdin_delivered_bytes": 0,
        "stdin_delivery_state": "not_requested" if stdin_data is None else "not_started",
        "stdin_delivery_complete": stdin_data is None,
        "stdout_path": str(artifacts_dir / "stdout.log"),
        "stderr_path": str(artifacts_dir / "stderr.log"),
        "native_receipts_dir": str(artifacts_dir / "runtime"),
        "events": [{"event": "wrapper_started", "elapsed_ms": 0}],
    }

    def event(name: str) -> None:
        receipt["events"].append({"event": name,
                                  "elapsed_ms": round((time.monotonic() - started) * 1000, 3)})

    _write_receipt(receipt_path, receipt)
    process: subprocess.Popen[bytes] | None = None
    capture: _OutputCapture | None = None
    cleanup_done = False
    try:
        if stdin_data is not None:
            _write_stdin_snapshot(Path(receipt["stdin_path"]), stdin_data)
            receipt["stdin_captured"] = True
            event("stdin_captured")
            _write_receipt(receipt_path, receipt)
        with open(receipt["stdout_path"], "xb", buffering=0) as stdout, \
                open(receipt["stderr_path"], "xb", buffering=0) as stderr:
            capture = _OutputCapture(stdout, stderr, max_output_bytes, stdin_data)
            if cancellation.signum is not None:
                return receipt
            if time.monotonic() >= started + wall_time_ms / 1000:
                receipt.update(outcome="wrapper_timeout", wrapper_exit_code=124,
                               wrapper_deadline_exceeded=True, timeout_layer="wrapper")
                event("wrapper_deadline_exceeded")
                return receipt
            try:
                process = subprocess.Popen(list(command), cwd=receipt["cwd"],
                                           stdin=subprocess.DEVNULL if stdin_data is None else subprocess.PIPE,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, bufsize=0, start_new_session=True)
            except OSError as error:
                receipt.update(outcome="spawn_error", error=str(error))
                event("wrapper_spawn_failed")
            else:
                receipt["runtime_pid"] = process.pid
                event("runtime_spawned")
                deadline = started + wall_time_ms / 1000
                try:
                    capture.attach(process)
                    # Persist the live PID before attempting any guest I/O.
                    _write_receipt(receipt_path, receipt)
                    while cancellation.signum is None:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            receipt.update(outcome="wrapper_timeout", wrapper_exit_code=124,
                                           wrapper_deadline_exceeded=True, timeout_layer="wrapper")
                            event("wrapper_deadline_exceeded")
                            break
                        capture.pump(min(remaining, 0.05))
                        if capture.exceeded:
                            receipt.update(outcome="output_limit_exceeded", fail_closed=True,
                                           wrapper_exit_code=125)
                            event("wrapper_output_limit_exceeded")
                            break
                        returncode = process.poll()
                        if returncode is not None:
                            receipt.update(outcome="completed" if returncode == 0 else "runtime_failed",
                                           fail_closed=returncode != 0,
                                           wrapper_exit_code=returncode if returncode >= 0 else 128 - returncode)
                            event("runtime_exited")
                            break
                    if cancellation.signum is not None and receipt["outcome"] == "running":
                        receipt.update(outcome="cancelled", fail_closed=True,
                                       wrapper_exit_code=128 + cancellation.signum)
                finally:
                    receipt["cleanup"] = _stop_process(process, kill_grace_ms, capture)
                    cleanup_done = True
                    receipt["runtime_exit_code"] = process.returncode
                    event("runtime_scope_stopped")
                if not receipt["cleanup"]["leader_reaped"]:
                    receipt.update(outcome="cleanup_failed", fail_closed=True, wrapper_exit_code=125)
                elif capture.error is not None:
                    receipt.update(outcome="supervisor_error", fail_closed=True, wrapper_exit_code=125)
    except BaseException as error:
        # Mark failure before retrying cleanup: a signalling failure must never
        # leave an earlier native exit-zero result published as success.
        receipt.update(outcome="supervisor_error", fail_closed=True, wrapper_exit_code=125,
                       error=f"{type(error).__name__}: {error}")
        event("wrapper_failed")
        if process is not None and not cleanup_done:
            try:
                receipt["cleanup"] = _stop_process(process, kill_grace_ms, capture)
            except OSError as cleanup_error:
                receipt["cleanup"] = {"scope": "process_group", "leader_reaped": False,
                                      "error": str(cleanup_error)}
            receipt["runtime_exit_code"] = process.returncode
        raise
    finally:
        if capture is not None:
            capture.record(receipt)
            capture.close()
            # The last buffered bytes can cross the quota after the leader has
            # exited zero. Incomplete or truncated evidence is never a success.
            if receipt["outcome"] in ("running", "completed", "runtime_failed"):
                if capture.exceeded:
                    receipt.update(outcome="output_limit_exceeded", fail_closed=True, wrapper_exit_code=125)
                    event("wrapper_output_limit_exceeded")
                elif process is not None and not receipt["output_complete"]:
                    receipt.update(outcome="output_incomplete", fail_closed=True, wrapper_exit_code=125)
                    event("wrapper_output_incomplete")
            if receipt["outcome"] == "completed" and not receipt["stdin_delivery_complete"]:
                receipt.update(outcome="input_incomplete", fail_closed=True, wrapper_exit_code=125)
                event("wrapper_input_incomplete")
        if cancellation.signum is not None:
            receipt["cancellation_signal"] = cancellation.signum
            event("wrapper_cancelled")
            # Preserve an already observed deadline or cleanup failure. A
            # cancellation cannot turn any prior failure into a success.
            if receipt["outcome"] in ("running", "completed", "runtime_failed"):
                receipt.update(outcome="cancelled", fail_closed=True,
                               wrapper_exit_code=128 + cancellation.signum)
        receipt["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
        for stream in ("stdout", "stderr"):
            path = Path(receipt[f"{stream}_path"])
            receipt[f"{stream}_bytes"] = path.stat().st_size if path.exists() else 0
        _write_receipt(receipt_path, receipt)
    return receipt


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--franken-node-bin", default="franken-node")
    parser.add_argument("--artifacts-dir", required=True, type=Path)
    parser.add_argument("--wall-time-ms", default=30000, type=positive_ms)
    parser.add_argument("--kill-grace-ms", default=250, type=positive_ms)
    parser.add_argument("--max-output-bytes", default=DEFAULT_MAX_OUTPUT_BYTES, type=positive_bytes,
                        help="maximum retained bytes per output stream (default: 16777216)")
    parser.add_argument("--stdin-file", type=Path,
                        help="capture a bounded regular file and deliver its binary bytes through stdin")
    parser.add_argument("--max-stdin-bytes", default=DEFAULT_MAX_STDIN_BYTES, type=positive_bytes,
                        help="maximum captured stdin size (default: 16777216)")
    parser.add_argument("--cwd", type=Path)
    parser.add_argument("runtime_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    runtime_args = args.runtime_args
    if runtime_args[:1] == ["--"]:
        runtime_args = runtime_args[1:]
    if not runtime_args:
        parser.error("supply runtime invoke arguments after -- (including an entrypoint)")
    if any(arg == "--output-dir" or arg.startswith("--output-dir=") for arg in runtime_args):
        parser.error("the watchdog owns --output-dir; use --artifacts-dir instead")
    # Resolve before changing the child's cwd, including relative binary paths.
    executable = shutil.which(args.franken_node_bin)
    binary = str(Path(executable).resolve()) if executable else str(Path(args.franken_node_bin).resolve())
    command = [binary, "runtime", "invoke", "--output-dir",
               str(args.artifacts_dir.resolve() / "runtime"), *runtime_args]
    try:
        with cancellation_signals() as cancellation:
            stdin_data = (read_stdin_file(args.stdin_file, args.max_stdin_bytes)
                          if args.stdin_file is not None else None)
            receipt = supervise(command, args.artifacts_dir, wall_time_ms=args.wall_time_ms,
                                kill_grace_ms=args.kill_grace_ms, cwd=args.cwd,
                                max_output_bytes=args.max_output_bytes,
                                stdin_data=stdin_data, max_stdin_bytes=args.max_stdin_bytes,
                                cancellation=cancellation)
    except (OSError, ValueError) as error:
        print(f"runtime watchdog: {error}", file=sys.stderr)
        return 125
    print(json.dumps(receipt, sort_keys=True))
    return int(receipt["wrapper_exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
