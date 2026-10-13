"""Cancellation of real JSON capture/replay/fix processes, not runtime parity.

Node is explicitly selected for both roles. Tests target owned process groups;
no assertion claims to reap nonchildren or contain descendants that escape them.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import failure_replay as replay

runner = replay.runner


@unittest.skipUnless(os.name == "posix" and shutil.which("node"), "real Node and POSIX required")
class ReplayCancellationTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="replay-cancel-tests-")
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.before, self.after = self.root / "before", self.root / "after"
        self.before.mkdir()
        self.after.mkdir()
        self.block = self.root / "block"
        self.command = [shutil.which("node"), "{test}", "{arguments}"]
        self.processes = []
        self.addCleanup(self.cleanup_processes)
        self.add_probe("probe.test.cjs")

    def add_probe(self, name):
        for role, project in (("baseline", self.before), ("migration", self.after)):
            marker = str(self.root / f"{name}-{role}")
            child_source = ("require('fs').writeFileSync(" + json.dumps(marker + ".child")
                            + ", String(process.pid));setInterval(()=>{},1000);")
            source = ("const fs=require('fs');\n"
                      f"if (fs.existsSync({json.dumps(str(self.block))})) {{\n"
                      "  fs.writeSync(1, 'private-partial-output\\n');\n"
                      f"  fs.writeFileSync({json.dumps(marker + '.parent')}, String(process.pid));\n"
                      "  require('child_process').spawn(process.execPath,['-e',"
                      + json.dumps(child_source) + "],{stdio:'ignore'});\n"
                      "  setInterval(()=>{},1000);\n"
                      f"}} else {{ console.log({json.dumps(role)}); }}\n")
            (project / name).write_text(source, encoding="utf-8")

    def configure(self, tests, *, concurrency=1, stdin_mode=None):
        for project in (self.before, self.after):
            raw = {"schema_version": runner.MIGRATION_TEST_SCHEMA,
                   "tests": tests, "max_concurrent_tests": concurrency}
            if stdin_mode:
                (project / "request.bin").write_bytes(b"x" * runner.MAX_INPUT_BYTES)
                raw["execution"] = {name: {"stdin": "request.bin", "stdin_mode": stdin_mode}
                                    for name in tests}
            (project / ".franken-node").mkdir(exist_ok=True)
            (project / runner.MIGRATION_TEST_MANIFEST).write_text(json.dumps(raw))

    def capture(self, **kwargs):
        return replay.capture_migration(self.before, migrated_project=self.after,
            baseline_command=self.command, migration_command=self.command,
            timeout_seconds=20, total_timeout_seconds=60, **kwargs)

    def capsule(self):
        artifact = self.capture()
        path = self.root / "original.json"
        replay.write_capsule(artifact, path)
        return artifact, path

    def launch(self, *options):
        command = [sys.executable, replay.__file__, "--json", *map(str, options),
                   "--baseline-command", json.dumps(self.command),
                   "--migration-command", json.dumps(self.command)]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        self.processes.append(process)
        return process

    def wait_ready(self, process=None, *, name="probe.test.cjs", role="baseline"):
        parent = self.root / f"{name}-{role}.parent"
        child = self.root / f"{name}-{role}.child"
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if parent.exists() and child.exists() and parent.stat().st_size and child.stat().st_size:
                return int(parent.read_text()), int(child.read_text())
            if process is not None and process.poll() is not None:
                stdout, stderr = process.communicate()
                self.fail(f"CLI exited before guest admission: {stdout!r} {stderr!r}")
            time.sleep(0.01)
        self.fail("guest did not reach the controlled blocking point")

    def cleanup_processes(self):
        # Only PIDs written by this test's own admitted Node leaders are used.
        for marker in self.root.glob("*.parent"):
            with contextlib.suppress(ProcessLookupError, ValueError):
                os.killpg(int(marker.read_text()), signal.SIGKILL)
        for process in self.processes:
            if process.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.communicate(timeout=5)

    @staticmethod
    def running(pid):
        proc = Path(f"/proc/{pid}/stat")
        if Path("/proc/self/stat").exists():
            try:
                return proc.read_text().rsplit(")", 1)[1].split()[0] != "Z"
            except FileNotFoundError:
                return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True

    def interrupted(self, process, signum, pids):
        process.send_signal(signum)
        stdout, stderr = process.communicate(timeout=8)
        self.assertEqual(process.returncode, 128 + signum, (stdout, stderr))
        result = json.loads(stdout)
        self.assertEqual(result["verdict"], "ERROR")
        self.assertEqual(result["cancellation"], {"signal": signum, "requested": True})
        self.assertNotIn("private-partial-output", stdout.decode())
        self.assertNotIn("Traceback", stderr.decode())
        deadline = time.monotonic() + 2
        while any(self.running(pid) for pid in pids) and time.monotonic() < deadline:
            time.sleep(0.01)
        for pid in pids:
            self.assertFalse(self.running(pid), f"owned process {pid} still running after CLI returned")
        return result

    def test_sigterm_capture_drains_children_and_keeps_partial_diagnostics(self):
        self.block.touch()
        destination = self.root / "capture.json"
        process = self.launch("--capture", self.before, "--migrated-project", self.after,
                              "--out", destination)
        pids = self.wait_ready(process)
        result = self.interrupted(process, signal.SIGTERM, pids)
        self.assertFalse(destination.exists(), "partial execution is not a replayable capsule")
        row = result["execution"]["validation_results"][0]
        self.assertEqual(row["baseline"]["termination"], "cancelled")
        self.assertNotIn("migration", row)
        self.assertGreaterEqual(row["baseline"]["streams"]["stdout"]["bytes_observed"], 23)
        self.assertFalse(row["baseline"]["streams"]["stdout"]["complete"])

    def test_sigint_replay_preserves_input_and_writes_private_partial_report(self):
        for project in (self.before, self.after):
            (project / "a.test.cjs").write_text("console.log('passing sibling');\n")
        artifact, path = self.capsule()
        original = path.read_bytes()
        self.block.touch()
        report_path = self.root / "replay.json"
        process = self.launch("--replay", path, "--execute", "--expected-sha256",
                              artifact["content_sha256"], "--out", report_path)
        result = self.interrupted(process, signal.SIGINT, self.wait_ready(process))
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(json.loads(report_path.read_bytes()), result)
        self.assertEqual(report_path.stat().st_mode & 0o777, 0o600)
        rows = result["execution"]["validation_results"]
        self.assertEqual(rows[0]["status"], "PASS")
        self.assertEqual(rows[1]["baseline"]["termination"], "cancelled")
        self.assertFalse((self.root / "probe.test.cjs-migration.parent").exists())

    def test_runtime_fix_cancellation_never_returns_fix_verified(self):
        artifact, path = self.capsule()
        self.block.touch()
        process = self.launch("--replay", path, "--execute", "--verify-fix",
                              "--expected-sha256", artifact["content_sha256"])
        result = self.interrupted(process, signal.SIGTERM, self.wait_ready(process))
        self.assertNotEqual(result["verdict"], "FIX_VERIFIED")
        self.assertEqual(replay.load_replay(path), artifact)

    def test_source_fix_admission_still_uses_cancelled_supervision(self):
        artifact, path = self.capsule()
        candidate = self.root / "fixed"
        shutil.copytree(self.after, candidate)
        before = (candidate / "probe.test.cjs").read_bytes()
        self.block.touch()
        process = self.launch("--replay", path, "--execute", "--verify-fix",
                              "--candidate-project", candidate,
                              "--expected-sha256", artifact["content_sha256"])
        result = self.interrupted(process, signal.SIGTERM, self.wait_ready(process))
        self.assertIn("execution", result)
        self.assertEqual((candidate / "probe.test.cjs").read_bytes(), before)
        self.assertEqual(replay.load_replay(path), artifact)

    def test_parallel_capture_cancels_every_active_pair_without_later_admission(self):
        for name in ("second.test.cjs", "third.test.cjs"):
            self.add_probe(name)
        self.configure(["probe.test.cjs", "second.test.cjs", "third.test.cjs"], concurrency=2)
        self.block.touch()
        process = self.launch("--capture", self.before, "--migrated-project", self.after,
                              "--out", self.root / "capture.json")
        pids = self.wait_ready(process) + self.wait_ready(process, name="second.test.cjs")
        result = self.interrupted(process, signal.SIGTERM, pids)
        self.assertEqual(result["execution"]["summary"]["skipped"], 1)
        self.assertEqual(len(result["execution"]["validation_results"]), 2)
        self.assertFalse((self.root / "third.test.cjs-baseline.parent").exists())
        self.assertEqual(list(self.root.glob("*-migration.parent")), [])

    def test_pipe_backpressure_and_file_stdin_both_cancel(self):
        for mode in ("pipe", "file"):
            with self.subTest(mode=mode):
                self.configure(["probe.test.cjs"], stdin_mode=mode)
                self.block.touch(exist_ok=True)
                # Distinct probe markers avoid observing a previous process.
                name = f"{mode}.test.cjs"
                self.add_probe(name)
                self.configure([name], stdin_mode=mode)
                process = self.launch("--capture", self.before, "--migrated-project", self.after,
                                      "--out", self.root / f"{mode}.json")
                result = self.interrupted(process, signal.SIGTERM, self.wait_ready(process, name=name))
                row = result["execution"]["validation_results"][0]
                self.assertEqual(row["baseline"]["stdin_transport"], mode)
                self.assertFalse((self.root / f"{mode}.json").exists())

    def test_library_cancellation_raises_with_evidence_without_owning_signals(self):
        previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        cancellation = runner.CancellationState()
        self.block.touch()
        def request():
            self.wait_ready()
            cancellation.request(signal.SIGTERM)
            cancellation.request(signal.SIGINT)
        watcher = threading.Thread(target=request)
        watcher.start()
        try:
            with self.assertRaises(replay.ReplayCancelled) as error:
                self.capture(cancellation=cancellation)
        finally:
            watcher.join(timeout=10)
        self.assertFalse(watcher.is_alive())
        self.assertEqual(cancellation.signum, signal.SIGTERM)
        self.assertIn("validation_results", error.exception.execution)
        self.assertEqual(previous, {sig: signal.getsignal(sig) for sig in previous})
        self.block.rename(self.root / "no-longer-blocked")
        self.assertEqual(self.capture()["expected"]["validation_verdict"], "FAIL")

    def test_precancelled_library_entrypoints_touch_no_files_or_runtimes(self):
        cancellation = runner.CancellationState(signum=signal.SIGINT)
        calls = [
            lambda: replay.capture_migration(self.root / "missing", cancellation=cancellation),
            lambda: replay.replay_migration({}, execute=True, cancellation=cancellation),
            lambda: replay.execute_snapshots({}, [], [], {}, cancellation=cancellation),
            lambda: replay.hash_regular_file(self.root / "missing", 0, cancellation=cancellation),
            lambda: replay.runtime_bindings([], [], 0, cancellation=cancellation),
            lambda: replay.load_replay(self.root / "missing", cancellation=cancellation),
            lambda: replay.inspect_capsule({}, cancellation=cancellation),
            lambda: replay.write_capsule({}, self.root / "missing", cancellation=cancellation),
            lambda: replay._capture_source_fix({}, {}, self.root / "missing", 0, cancellation=cancellation),
            lambda: replay.self_test(cancellation=cancellation),
        ]
        with mock.patch.object(runner, "run_command") as launch:
            for call in calls:
                with self.assertRaises(runner.ExecutionCancelled):
                    call()
        launch.assert_not_called()
        self.assertFalse((self.root / "missing").exists())

    def test_cancellation_after_staging_prevents_any_guest_launch(self):
        artifact = self.capture()
        snapshots = replay.validate_capsule(artifact)
        cancellation = runner.CancellationState()
        original = runner.stage_project
        def stage(*args, **kwargs):
            original(*args, **kwargs)
            cancellation.request(signal.SIGTERM)
        with mock.patch.object(runner, "stage_project", side_effect=stage), \
             mock.patch.object(runner, "run_command") as launch:
            with self.assertRaises(runner.ExecutionCancelled):
                replay.execute_snapshots(snapshots, self.command, self.command,
                                          artifact["options"], cancellation=cancellation)
        launch.assert_not_called()

    def test_cancellation_during_post_run_identity_check_retains_completed_rows(self):
        cancellation = runner.CancellationState()
        original = replay.runtime_bindings
        phases = []
        def bindings(*args, **kwargs):
            phases.append(True)
            if len(phases) == 2:
                cancellation.request(signal.SIGTERM)
            return original(*args, **kwargs)
        with mock.patch.object(replay, "runtime_bindings", side_effect=bindings):
            with self.assertRaises(replay.ReplayCancelled) as error:
                self.capture(cancellation=cancellation)
        self.assertEqual(len(error.exception.execution["validation_results"]), 1)
        self.assertEqual(error.exception.execution["validation_results"][0]["status"], "FAIL")

    def test_hash_and_load_poll_cancellation_between_bounded_reads(self):
        path = self.root / "large.json"
        note = replay.capture_failure("test", "fixture", {"payload": "x" * (2 * 1024 * 1024)}, {}, {})
        replay.write_capsule(note, path)
        original = os.fdopen
        for operation in (lambda state: replay.load_replay(path, cancellation=state),
                          lambda state: replay.hash_regular_file(path, time.monotonic() + 5, cancellation=state)):
            cancellation = runner.CancellationState()
            reads = []
            class InterruptingReader:
                def __init__(self, stream): self.stream = stream
                def __enter__(self): return self
                def __exit__(self, *args): return self.stream.__exit__(*args)
                def fileno(self): return self.stream.fileno()
                def read(self, size):
                    reads.append(size)
                    data = self.stream.read(size)
                    cancellation.request(signal.SIGTERM)
                    return data
            with mock.patch.object(os, "fdopen", side_effect=lambda *a, **k: InterruptingReader(original(*a, **k))):
                with self.assertRaises(runner.ExecutionCancelled):
                    operation(cancellation)
            self.assertEqual(reads, [1024 * 1024])

    def test_late_publication_signal_keeps_complete_capsule_but_reports_interruption(self):
        cancellation = runner.CancellationState()
        output = self.root / "complete.json"
        args = SimpleNamespace(self_test=False, inspect=None, replay=None, capture=self.before,
            migrated_project=self.after, out=output, baseline_command=self.command,
            migration_command=self.command, compare_filesystem=False,
            timeout_seconds=5, total_timeout_seconds=20, json=True)
        original = replay.write_capsule
        def publish(*args, **kwargs):
            original(*args, **kwargs)
            cancellation.request(signal.SIGTERM)
        text = io.StringIO()
        with mock.patch.object(replay, "write_capsule", side_effect=publish), contextlib.redirect_stdout(text):
            code = replay._execute_cli(args, cancellation)
        result = json.loads(text.getvalue())
        self.assertEqual(code, 143)
        self.assertEqual(result["verdict"], "ERROR")
        self.assertEqual(result["path"], str(output))
        self.assertEqual(replay.inspect_capsule(replay.load_replay(output))["verdict"], "INTEGRITY_VALID")

    def test_cli_rejects_input_overwrite_before_execution(self):
        artifact, path = self.capsule()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        self.block.touch()
        process = self.launch("--replay", path, "--execute", "--out", path)
        stdout, stderr = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 2, (stdout, stderr))
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        self.assertEqual(list(self.root.glob("*.parent")), [])

    def test_main_restores_previous_signal_handlers(self):
        previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        text = io.StringIO()
        with mock.patch.object(sys, "argv", [replay.__file__, "--self-test", "--json"]), contextlib.redirect_stdout(text):
            self.assertEqual(replay.main(), 0)
        self.assertEqual(json.loads(text.getvalue())["verdict"], "PASS")
        self.assertEqual(previous, {sig: signal.getsignal(sig) for sig in previous})


if __name__ == "__main__":
    unittest.main()
