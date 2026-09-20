"""Cancellation against real owned processes; this is not a sandbox guarantee."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts/migration_validation_runner.py"
SPEC = importlib.util.spec_from_file_location("migration_cancel_runner", SOURCE)
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


@unittest.skipUnless(os.name == "posix", "POSIX process-group supervision required")
class CancellationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="migration-cancellation-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.before = self.root / "before"
        self.after = self.root / "after"
        self.before.mkdir()
        self.after.mkdir()
        self.bundle = self.root / "capture.fnmigration"
        self.report = self.root / "report.json"
        self.ready = self.root / "ready.pid"
        self.descendant = self.root / "descendant.pid"
        self.candidate = self.root / "candidate-ran"
        self.command = [sys.executable, "{test}"]
        for root in (self.before, self.after):
            (root / "case.test.js").write_text("print('same')\n")

    def execute(self, **kwargs):
        return runner.validate_project(self.before, migrated_project=self.after,
            baseline_command=self.command, migration_command=self.command,
            timeout_seconds=5, total_timeout_seconds=30, bundle_path=self.bundle, **kwargs)

    def wait_ready(self, process):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and process.poll() is None:
            if self.ready.exists() and self.ready.read_text():
                return int(self.ready.read_text())
            time.sleep(0.01)
        self.fail(f"guest never became ready; runner status {process.poll()}")

    def active(self, pid):
        try:
            # Grandchildren killed in the group may be zombies owned by init;
            # they cannot run or retain pipes. Do not claim we reaped them.
            proc = Path(f"/proc/{pid}/stat")
            if proc.exists():
                return proc.read_text().rsplit(")", 1)[1].strip().split()[0] != "Z"
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, FileNotFoundError):
            return False

    def assert_stopped(self, pid):
        deadline = time.monotonic() + 3
        while self.active(pid) and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertFalse(self.active(pid), f"guest {pid} still executing")

    def blocked_source(self, descendant=False):
        source = "import os,sys,time,signal,subprocess\nfrom pathlib import Path\n"
        source += "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        if descendant:
            child = ("import os,time,signal;from pathlib import Path;"
                     "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
                     f"Path({str(self.descendant)!r}).write_text(str(os.getpid()));time.sleep(60)")
            source += f"subprocess.Popen([sys.executable, '-c', {child!r}])\n"
            source += f"while not Path({str(self.descendant)!r}).exists(): time.sleep(.01)\n"
        source += "sys.stdout.buffer.write(b'partial\\x00\\xff');sys.stdout.flush()\n"
        source += f"Path({str(self.ready)!r}).write_text(str(os.getpid()))\ntime.sleep(60)\n"
        return source

    def stop_cleanup(self, process, pid=None):
        if pid is not None and self.active(pid):
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)

    def cli(self):
        return [sys.executable, str(SOURCE), str(self.before), "--migrated-project", str(self.after),
                "--baseline-command", json.dumps(self.command), "--migration-command", json.dumps(self.command),
                "--bundle", str(self.bundle), "--out", str(self.report), "--json"]

    def cancelled_cli(self, signum, repeated=False, descendant=False):
        (self.before / "case.test.js").write_text(self.blocked_source(descendant))
        (self.after / "case.test.js").write_text(
            f"from pathlib import Path\nPath({str(self.candidate)!r}).write_text('ran')\n")
        for root in (self.before, self.after):
            (root / "z.test.js").write_text("print('must be skipped')\n")
        process = subprocess.Popen(self.cli(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        pid = None
        try:
            pid = self.wait_ready(process)
            process.send_signal(signum)
            if repeated:
                # A second kind of signal must not interrupt cleanup or replace
                # first-signal attribution. No handler injection in the product.
                time.sleep(0.005)
                if process.poll() is None:
                    process.send_signal(signal.SIGINT if signum == signal.SIGTERM else signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 128 + signum, stderr)
            report = json.loads(stdout)
            self.assertEqual(report, json.loads(self.report.read_text()))
            self.assertEqual(report["summary"]["verdict"], "ERROR", report)
            self.assertEqual(report["summary"]["errored"], 1)
            self.assertEqual(report["summary"]["skipped"], 1)
            self.assertEqual(report["cancellation"]["signal"], signum)
            row = report["validation_results"][0]
            self.assertEqual(row["baseline"]["termination"], "cancelled")
            self.assertNotIn("migration", row)
            self.assertFalse(self.candidate.exists())
            self.assert_stopped(pid)
            if descendant:
                self.assert_stopped(int(self.descendant.read_text()))
            bundle = runner.read_replay_bundle(self.bundle, expected_sha256=report["replay_bundle"]["sha256"])
            self.assertEqual(bundle.manifest["report"]["summary"]["verdict"], "ERROR")
            observation = bundle.manifest["observations"][0]
            self.assertEqual(bundle.objects[observation["stdout"]], b"partial\x00\xff")
            self.assertFalse(row["baseline"]["streams"]["stdout"]["complete"])
            self.assertEqual(len(bundle.manifest["observations"]), 1)
            rejected = runner.replay_captured_bundle(self.bundle,
                expected_sha256=report["replay_bundle"]["sha256"],
                baseline_command=self.command, migration_command=self.command)
            self.assertEqual(rejected["replay_outcome"], "ERROR")
            self.assertIn("can be inspected", rejected["errors"][0]["message"])
        finally:
            self.stop_cleanup(process, pid)

    def test_sigterm_stops_guest_and_preserves_partial_bundle(self):
        self.cancelled_cli(signal.SIGTERM)

    def test_sigint_is_an_error_with_evidence_not_keyboardinterrupt_loss(self):
        self.cancelled_cli(signal.SIGINT)

    def test_repeated_signals_do_not_interrupt_cleanup_or_launch_candidate(self):
        self.cancelled_cli(signal.SIGTERM, repeated=True, descendant=True)

    def test_precancelled_library_call_never_launches_or_installs_handlers(self):
        before = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
        token = runner.CancellationState()
        token.request(signal.SIGINT)
        with patch.object(runner.subprocess, "Popen", side_effect=AssertionError("must not launch")):
            report = self.execute(cancellation=token)
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertEqual(report["cancellation"]["signal"], signal.SIGINT)
        self.assertFalse(self.bundle.exists())
        self.assertEqual(before, {s: signal.getsignal(s) for s in before})

    def test_signal_handlers_restore_after_exception_and_keep_first_signal(self):
        before = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
        token = runner.CancellationState()
        with self.assertRaisesRegex(RuntimeError, "sentinel"):
            with runner.termination_signals(token):
                os.kill(os.getpid(), signal.SIGTERM)
                os.kill(os.getpid(), signal.SIGINT)
                self.assertEqual(token.signum, signal.SIGTERM)
                raise RuntimeError("sentinel")
        self.assertEqual(before, {s: signal.getsignal(s) for s in before})

    def test_cancellation_during_launch_still_owns_and_reaps_child(self):
        token = runner.CancellationState()
        real_popen = subprocess.Popen
        children = []
        def launch_then_cancel(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            token.request(signal.SIGTERM)
            return child
        (self.before / "case.test.js").write_text("import time\ntime.sleep(60)\n")
        with patch.object(runner.subprocess, "Popen", side_effect=launch_then_cancel):
            report = self.execute(cancellation=token)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        self.assert_stopped(children[0].pid)
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertEqual(report["validation_results"][0]["baseline"]["termination"], "cancelled")
        runner.read_replay_bundle(self.bundle)

    def test_cancellation_between_legs_preserves_completed_baseline(self):
        token = runner.CancellationState()
        real_run = runner.run_command
        def run_then_cancel(*args, **kwargs):
            result = real_run(*args, **kwargs)
            token.request(signal.SIGTERM)
            return result
        with patch.object(runner, "run_command", side_effect=run_then_cancel) as run:
            report = self.execute(cancellation=token)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertEqual(report["validation_results"][0]["baseline"]["termination"], "exited")
        captured = runner.read_replay_bundle(self.bundle)
        self.assertEqual(captured.objects[captured.manifest["observations"][0]["stdout"]], b"same\n")

    def test_cancellation_during_identity_recheck_cannot_certify_success(self):
        token = runner.CancellationState()
        real_measure = runner.measure_runtime_identities
        calls = 0
        def measure_then_cancel(*args, **kwargs):
            nonlocal calls
            measured = real_measure(*args, **kwargs)
            calls += 1
            if calls == 2:
                token.request(signal.SIGTERM)
            return measured
        with patch.object(runner, "measure_runtime_identities", side_effect=measure_then_cancel):
            report = self.execute(cancellation=token)
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertEqual(report["validation_results"][0]["status"], "PASS")
        bundle = runner.read_replay_bundle(self.bundle)
        self.assertEqual(bundle.manifest["report"]["summary"]["verdict"], "ERROR")

    def test_cancelled_replay_does_not_claim_reproduction(self):
        report = self.execute()
        token = runner.CancellationState(signal.SIGINT)
        with patch.object(runner.subprocess, "Popen", side_effect=AssertionError("must not launch")):
            outcome = runner.replay_captured_bundle(self.bundle,
                expected_sha256=report["replay_bundle"]["sha256"], baseline_command=self.command,
                migration_command=self.command, cancellation=token)
        self.assertEqual(outcome["replay_outcome"], "ERROR")
        self.assertEqual(outcome["cancellation"]["signal"], signal.SIGINT)

    def test_replay_cli_sigterm_stops_real_reexecution(self):
        # External state deliberately changes behavior on re-execution. The
        # input bytes, selected runtimes and effective environment remain fixed.
        trigger = self.root / "block-on-replay"
        source = f"from pathlib import Path\nif Path({str(trigger)!r}).exists():\n"
        source += "\n".join("    " + line for line in self.blocked_source().splitlines())
        source += "\nelse:\n    print('same')\n"
        for root in (self.before, self.after):
            (root / "case.test.js").write_text(source)
        report = self.execute()
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        trigger.write_text("block")
        command = [sys.executable, str(SOURCE), "--replay-bundle", str(self.bundle),
            "--expected-bundle-sha256", report["replay_bundle"]["sha256"],
            "--baseline-command", json.dumps(self.command), "--migration-command", json.dumps(self.command),
            "--json", "--out", str(self.report)]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        pid = None
        try:
            pid = self.wait_ready(process)
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 143, stderr)
            outcome = json.loads(stdout)
            self.assertEqual(outcome["replay_outcome"], "ERROR", outcome)
            self.assertEqual(outcome["execution"]["summary"]["verdict"], "ERROR")
            self.assertEqual(outcome["execution"]["validation_results"][0]["baseline"]["termination"], "cancelled")
            self.assertEqual(outcome, json.loads(self.report.read_text()))
            self.assert_stopped(pid)
            self.assertEqual(hashlib.sha256(self.bundle.read_bytes()).hexdigest(), report["replay_bundle"]["sha256"])
        finally:
            self.stop_cleanup(process, pid)


if __name__ == "__main__":
    unittest.main()
