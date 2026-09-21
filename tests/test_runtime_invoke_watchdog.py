"""Executable watchdog tests; no Rust toolchain or sibling repos required."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "runtime_invoke_watchdog.py"
spec = importlib.util.spec_from_file_location("runtime_invoke_watchdog", SCRIPT)
watchdog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watchdog)


@unittest.skipUnless(os.name == "posix", "requires POSIX process groups")
class WatchdogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.artifacts = self.root / "artifacts"

    def run_code(self, code, budget=2000, **kwargs):
        return watchdog.supervise([sys.executable, "-S", "-u", "-c", code], self.artifacts,
                                  wall_time_ms=budget, kill_grace_ms=100, **kwargs)

    def test_success_preserves_raw_streams_and_receipt(self):
        result = self.run_code("import os; os.write(1, b'output\\xff'); os.write(2, b'warning\\x00')")
        self.assertEqual(result["outcome"], "completed")
        self.assertFalse(result["fail_closed"])
        self.assertFalse(result["wrapper_deadline_exceeded"])
        self.assertEqual((self.artifacts / "stdout.log").read_bytes(), b"output\xff")
        self.assertEqual((self.artifacts / "stderr.log").read_bytes(), b"warning\x00")
        self.assertEqual(json.loads((self.artifacts / "watchdog.json").read_text()), result)

    def test_timeout_preserves_partial_evidence_and_stops_ignoring_process(self):
        result = self.run_code("import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                               "print('before hang',flush=True); time.sleep(60)", budget=1000)
        self.assertEqual(result["outcome"], "wrapper_timeout")
        self.assertEqual(result["wrapper_exit_code"], 124)
        self.assertEqual(result["runtime_exit_code"], -signal.SIGKILL)
        self.assertTrue(result["fail_closed"])
        self.assertTrue(result["wrapper_deadline_exceeded"])
        self.assertEqual(result["timeout_layer"], "wrapper")
        self.assertIn("before hang", (self.artifacts / "stdout.log").read_text())
        self.assertIn("wrapper_deadline_exceeded", [e["event"] for e in result["events"]])
        self.assertLess(result["elapsed_ms"], 4000)

    def test_native_exit_124_is_not_a_wrapper_timeout(self):
        result = self.run_code("raise SystemExit(124)")
        self.assertEqual(result["outcome"], "runtime_failed")
        self.assertEqual(result["wrapper_exit_code"], 124)
        self.assertFalse(result["wrapper_deadline_exceeded"])
        self.assertIsNone(result["timeout_layer"])

    def test_engine_budget_failure_is_not_reclassified(self):
        result = self.run_code("import sys; print('engine budget exhausted',file=sys.stderr); raise SystemExit(1)")
        self.assertEqual(result["outcome"], "runtime_failed")
        self.assertFalse(result["wrapper_deadline_exceeded"])
        self.assertIsNone(result["timeout_layer"])

    def test_native_crash_preserves_signal(self):
        result = self.run_code("import os,signal; os.kill(os.getpid(), signal.SIGTERM)")
        self.assertEqual(result["runtime_exit_code"], -signal.SIGTERM)
        self.assertEqual(result["wrapper_exit_code"], 128 + signal.SIGTERM)
        self.assertEqual(result["outcome"], "runtime_failed")

    def test_timeout_remains_failure_when_term_handler_exits_zero(self):
        result = self.run_code("import os,signal,time; signal.signal(signal.SIGTERM, lambda *_: os._exit(0)); time.sleep(60)", 1000)
        self.assertEqual(result["runtime_exit_code"], 0)
        self.assertEqual(result["outcome"], "wrapper_timeout")
        self.assertTrue(result["fail_closed"])

    def test_missing_binary_writes_failure_receipt(self):
        result = watchdog.supervise([str(self.root / "missing")], self.artifacts)
        self.assertEqual(result["outcome"], "spawn_error")
        self.assertEqual(result["wrapper_exit_code"], 125)
        self.assertTrue(result["fail_closed"])
        self.assertTrue((self.artifacts / "watchdog.json").exists())

    def test_existing_artifacts_are_never_reused(self):
        self.artifacts.mkdir()
        sentinel = self.artifacts / "watchdog.json"
        sentinel.write_text("previous evidence")
        with self.assertRaises(FileExistsError):
            self.run_code("pass")
        self.assertEqual(sentinel.read_text(), "previous evidence")

    def test_invalid_budget_never_launches(self):
        for value in ("0", "-1", "nan", "inf", "1.5", "86400001", "9" * 500):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                watchdog.positive_ms(value)
        with self.assertRaises(argparse.ArgumentTypeError):
            watchdog.supervise([sys.executable], self.artifacts, wall_time_ms=0)
        self.assertFalse(self.artifacts.exists())

    def test_large_output_drains_both_streams_without_deadlock(self):
        result = self.run_code("import os; os.write(1,b'x'*2000000); os.write(2,b'y'*2000000)")
        self.assertEqual(result["outcome"], "completed")
        self.assertEqual(result["stdout_bytes"], 2000000)
        self.assertEqual(result["stderr_bytes"], 2000000)

    def test_cli_invokes_real_run_command_and_preserves_policy_options(self):
        binary = self.root / "fake node"
        binary.write_text(f"#!{sys.executable}\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n")
        binary.chmod(0o700)
        completed = subprocess.run([sys.executable, str(SCRIPT), "--franken-node-bin", str(binary),
                                    "--artifacts-dir", str(self.artifacts), "--", "entry point.js",
                                    "--policy", "strict", "--console-only"], capture_output=True, text=True, timeout=5)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        received = json.loads((self.artifacts / "stdout.log").read_text())
        self.assertEqual(received, ["run", "entry point.js", "--policy", "strict", "--console-only"])
        self.assertIsNone(result["native_receipts_dir"])
        self.assertFalse((self.artifacts / "runtime").exists())
        self.assertEqual(result["outcome"], "completed")

    def test_cli_rejects_output_override(self):
        completed = subprocess.run([sys.executable, str(SCRIPT), "--artifacts-dir", str(self.artifacts),
                                    "--", "app.js", "--output-dir=/tmp/other"], capture_output=True, timeout=5)
        self.assertEqual(completed.returncode, 2)
        self.assertFalse(self.artifacts.exists())


    def assert_process_stopped(self, pid):
        # An orphan killed by the supervisor can remain a zombie until PID 1
        # reaps it; kill(pid, 0) alone incorrectly reports it as still running.
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
            except FileNotFoundError:
                return
            if state == "Z":
                return
            time.sleep(0.01)
        self.fail(f"process {pid} remained alive after cleanup")

    @unittest.skipUnless(Path("/proc/self/stat").exists(), "process-state assertion uses procfs")
    def test_descendant_ignoring_term_is_killed_after_leader_exits(self):
        code = """
import os,signal,time
reader,writer=os.pipe()
pid=os.fork()
if pid == 0:
    os.close(reader)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    os.write(writer,b'ready')
    os.close(writer)
    time.sleep(60)
else:
    os.close(writer)
    os.read(reader,5)
    print(pid,flush=True)
"""
        result = self.run_code(code)
        pid = int((self.artifacts / "stdout.log").read_text())
        self.assertEqual(result["outcome"], "completed")
        self.assertTrue(result["cleanup"]["kill_sent"])
        self.assert_process_stopped(pid)

    @unittest.skipUnless(Path("/proc/self/stat").exists(), "process-state assertion uses procfs")
    def test_deadline_stops_parent_and_descendant(self):
        code = """
import os,signal,time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
pid=os.fork()
if pid != 0:
    print(pid,flush=True)
time.sleep(60)
"""
        result = self.run_code(code, budget=1000)
        self.assertEqual(result["outcome"], "wrapper_timeout")
        pid = int((self.artifacts / "stdout.log").read_text())
        self.assert_process_stopped(pid)
        self.assert_process_stopped(result["runtime_pid"])

    def test_preexisting_cancellation_never_launches_runtime(self):
        cancellation = watchdog.Cancellation()
        cancellation.request(signal.SIGTERM)
        result = watchdog.supervise([str(self.root / "nonexistent")], self.artifacts,
                                    cancellation=cancellation)
        self.assertEqual(result["outcome"], "cancelled")
        self.assertEqual(result["wrapper_exit_code"], 143)
        self.assertNotIn("runtime_pid", result)
        self.assertTrue(result["fail_closed"])
        self.assertFalse(result["wrapper_deadline_exceeded"])

    def test_cancellation_preserves_first_signal_and_restores_handlers(self):
        previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
        with watchdog.cancellation_signals() as cancellation:
            cancellation.request(signal.SIGINT)
            cancellation.request(signal.SIGTERM)
            self.assertEqual(cancellation.signum, signal.SIGINT)
        for sig, handler in previous.items():
            self.assertEqual(signal.getsignal(sig), handler)

    def cancel_cli(self, sig, repeat=False, stdin_data=None):
        binary = self.root / "fake-node"
        ready = self.root / "ready"
        binary.write_text(f"#!{sys.executable}\nimport signal,time\nfrom pathlib import Path\n"
                          f"signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
                          f"Path({str(ready)!r}).write_text('ready')\ntime.sleep(60)\n")
        binary.chmod(0o700)
        stdin_args = []
        if stdin_data is not None:
            source = self.root / "request.bin"
            source.write_bytes(stdin_data)
            stdin_args = ["--stdin-file", str(source)]
        process = subprocess.Popen([sys.executable, str(SCRIPT), "--franken-node-bin", str(binary),
                                    "--artifacts-dir", str(self.artifacts), "--wall-time-ms", "10000",
                                    "--kill-grace-ms", "300", *stdin_args, "--", "app.js"],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        runtime_pid = None
        try:
            deadline = time.monotonic() + 6
            while time.monotonic() < deadline:
                receipt_path = self.artifacts / "watchdog.json"
                if receipt_path.exists():
                    receipt = json.loads(receipt_path.read_text())
                    runtime_pid = receipt.get("runtime_pid")
                    if ready.exists() and runtime_pid:
                        self.assertTrue(receipt["fail_closed"])
                        self.assertEqual(receipt["outcome"], "running")
                        break
                time.sleep(0.01)
            else:
                self.fail("native runtime did not become ready")
            process.send_signal(sig)
            if repeat:
                time.sleep(0.03)
                process.send_signal(signal.SIGINT)
            stdout, stderr = process.communicate(timeout=4)
            self.assertEqual(process.returncode, 128 + sig, stderr)
            result = json.loads(stdout)
            self.assertEqual(result["outcome"], "cancelled")
            self.assertEqual(result["cancellation_signal"], sig)
            self.assertFalse(result["wrapper_deadline_exceeded"])
            self.assertTrue(result["cleanup"]["leader_reaped"])
            self.assertEqual(result, json.loads((self.artifacts / "watchdog.json").read_text()))
            if stdin_data is not None:
                self.assertEqual((self.artifacts / "stdin.bin").read_bytes(), stdin_data)
                self.assertLess(result["stdin_delivered_bytes"], len(stdin_data))
                self.assertFalse(result["stdin_delivery_complete"])
        finally:
            if runtime_pid is not None:
                try:
                    os.killpg(runtime_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=3)

    def test_sigterm_cancellation_survives_a_second_signal(self):
        self.cancel_cli(signal.SIGTERM, repeat=True)

    def test_ctrl_c_cleans_up_runtime_and_publishes_receipt(self):
        self.cancel_cli(signal.SIGINT)

    def test_receipt_write_failure_after_spawn_stops_native_scope(self):
        original = watchdog._write_receipt
        count = 0

        def fail_once(path, receipt):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError("simulated storage failure after spawn")
            original(path, receipt)

        with mock.patch.object(watchdog, "_write_receipt", side_effect=fail_once):
            with self.assertRaisesRegex(OSError, "storage failure"):
                self.run_code("import time; time.sleep(60)")
        result = json.loads((self.artifacts / "watchdog.json").read_text())
        self.assertEqual(result["outcome"], "supervisor_error")
        self.assertTrue(result["fail_closed"])
        self.assertTrue(result["cleanup"]["leader_reaped"])

    def test_invalid_command_is_rejected_before_artifacts_are_created(self):
        for command in ("echo unsafe", [], [""], ["bad\x00binary"], [1]):
            with self.subTest(command=command), self.assertRaises(ValueError):
                watchdog.supervise(command, self.artifacts)
        self.assertFalse(self.artifacts.exists())


    def test_cleanup_error_cannot_publish_native_exit_zero_as_success(self):
        with mock.patch.object(watchdog, "_signal_group", side_effect=PermissionError("denied")):
            with self.assertRaises(PermissionError):
                self.run_code("pass")
        result = json.loads((self.artifacts / "watchdog.json").read_text())
        self.assertEqual(result["runtime_exit_code"], 0)
        self.assertEqual(result["outcome"], "supervisor_error")
        self.assertEqual(result["wrapper_exit_code"], 125)
        self.assertTrue(result["fail_closed"])


    def test_output_limit_validation_precedes_launch_and_artifacts(self):
        for value in ("0", "-1", "nan", "inf", "1.5", "1073741825", "9" * 500):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                watchdog.positive_bytes(value)
        with self.assertRaises(argparse.ArgumentTypeError):
            self.run_code("pass", max_output_bytes=0)
        self.assertFalse(self.artifacts.exists())

    def test_exact_output_limit_preserves_binary_bytes_and_completeness(self):
        payload = bytes(range(256)) * 16
        result = self.run_code("import os; data=bytes(range(256))*16; "
                               "os.write(1,data); os.write(2,data)", max_output_bytes=len(payload))
        self.assertEqual(result["outcome"], "completed")
        self.assertTrue(result["output_complete"])
        self.assertFalse(result["output_limit_exceeded"])
        for stream in ("stdout", "stderr"):
            self.assertEqual((self.artifacts / f"{stream}.log").read_bytes(), payload)
            self.assertEqual(result[f"{stream}_observed_bytes"], len(payload))
            self.assertTrue(result[f"{stream}_eof"])

    def test_stdout_flood_is_stopped_at_quota_not_wall_deadline(self):
        result = self.run_code("import os,signal; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                               "os.write(2,b'diagnostic'); "
                               "exec(\"while True: os.write(1,b'\\\\xff'*65536)\")",
                               max_output_bytes=32768)
        self.assertEqual(result["outcome"], "output_limit_exceeded")
        self.assertEqual(result["wrapper_exit_code"], 125)
        self.assertEqual(result["output_limit_streams"], ["stdout"])
        self.assertEqual(result["stdout_bytes"], 32768)
        self.assertEqual((self.artifacts / "stdout.log").read_bytes(), b"\xff" * 32768)
        self.assertGreater(result["stdout_observed_bytes"], 32768)
        self.assertEqual((self.artifacts / "stderr.log").read_bytes(), b"diagnostic")
        self.assertTrue(result["fail_closed"])
        self.assertFalse(result["wrapper_deadline_exceeded"])
        self.assertFalse(result["output_complete"])
        self.assertTrue(result["cleanup"]["leader_reaped"])
        self.assertEqual(result["runtime_exit_code"], -signal.SIGKILL)
        self.assertLess(result["elapsed_ms"], 1500)

    def test_stderr_is_subject_to_the_same_quota(self):
        result = self.run_code("import os; os.write(2,b'e'*8192)", max_output_bytes=1024)
        self.assertEqual(result["outcome"], "output_limit_exceeded")
        self.assertEqual(result["output_limit_streams"], ["stderr"])
        self.assertEqual((self.artifacts / "stderr.log").read_bytes(), b"e" * 1024)
        self.assertGreater(result["stderr_observed_bytes"], 1024)
        self.assertFalse(result["stderr_complete"])

    def test_overflow_in_buffered_tail_cannot_publish_native_exit_zero(self):
        attach = watchdog._OutputCapture.attach

        def attach_after_exit(capture, process):
            attach(capture, process)
            process.wait(timeout=2)  # Eight bytes fit in the real OS pipe.

        with mock.patch.object(watchdog._OutputCapture, "attach", attach_after_exit), \
                mock.patch.object(watchdog, "IO_CHUNK_BYTES", 4):
            result = self.run_code("import os; os.write(1,b'abcdefgh')", max_output_bytes=4)
        self.assertEqual(result["runtime_exit_code"], 0)
        self.assertEqual(result["outcome"], "output_limit_exceeded")
        self.assertEqual((self.artifacts / "stdout.log").read_bytes(), b"abcd")
        self.assertEqual(result["stdout_observed_bytes"], 8)
        self.assertTrue(result["fail_closed"])

    def test_timeout_cause_survives_overflow_during_term_handler(self):
        code = """
import os,signal,time
def stop(*_):
    os.write(1,b'x'*8192)
    raise SystemExit(0)
signal.signal(signal.SIGTERM,stop)
time.sleep(60)
"""
        result = self.run_code(code, budget=400, max_output_bytes=32)
        self.assertEqual(result["outcome"], "wrapper_timeout")
        self.assertTrue(result["wrapper_deadline_exceeded"])
        self.assertTrue(result["output_limit_exceeded"])
        self.assertEqual(result["stdout_bytes"], 32)
        self.assertTrue(result["fail_closed"])

    def test_both_streams_continue_draining_during_cleanup_without_growing_logs(self):
        code = """
import os,signal,time
signal.signal(signal.SIGTERM,signal.SIG_IGN)
for _ in range(20):
    os.write(1,b'x'*16384)
    os.write(2,b'y'*16384)
time.sleep(60)
"""
        result = self.run_code(code, max_output_bytes=32768)
        self.assertEqual(result["outcome"], "output_limit_exceeded")
        self.assertEqual(result["output_limit_streams"], ["stderr", "stdout"])
        self.assertEqual(result["stdout_bytes"], 32768)
        self.assertEqual(result["stderr_bytes"], 32768)
        self.assertTrue(result["cleanup"]["leader_reaped"])

    def test_closed_streams_do_not_disable_wall_deadline(self):
        result = self.run_code("import os,time; os.close(1); os.close(2); time.sleep(60)", budget=300)
        self.assertEqual(result["outcome"], "wrapper_timeout")
        self.assertTrue(result["stdout_eof"])
        self.assertTrue(result["stderr_eof"])
        self.assertLess(result["elapsed_ms"], 1500)

    def test_detached_pipe_holder_is_bounded_and_cannot_claim_complete_success(self):
        pid_file = self.root / "detached-pid"
        code = f"""
import os,time
from pathlib import Path
reader,writer=os.pipe()
pid=os.fork()
if pid == 0:
    os.close(reader)
    os.setsid()
    Path({str(pid_file)!r}).write_text(str(os.getpid()))
    os.write(writer,b'ready')
    os.close(writer)
    time.sleep(60)
else:
    os.close(writer)
    os.read(reader,5)
    print('parent finished',flush=True)
"""
        try:
            result = self.run_code(code)
            self.assertEqual(result["runtime_exit_code"], 0)
            self.assertEqual(result["outcome"], "output_incomplete")
            self.assertTrue(result["fail_closed"])
            self.assertFalse(result["output_complete"])
            self.assertFalse(result["wrapper_deadline_exceeded"])
            self.assertLess(result["elapsed_ms"], 1500)
        finally:
            if pid_file.exists():
                try:
                    os.kill(int(pid_file.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_capture_storage_failure_still_stops_and_reaps_runtime(self):
        attach = watchdog._OutputCapture.attach

        def attach_failing_sink(capture, process):
            attach(capture, process)
            capture.sinks["stdout"] = mock.Mock()
            capture.sinks["stdout"].write.side_effect = OSError("log storage unavailable")

        with mock.patch.object(watchdog._OutputCapture, "attach", attach_failing_sink):
            with self.assertRaisesRegex(OSError, "log storage"):
                self.run_code("import time; print('data',flush=True); time.sleep(60)")
        result = json.loads((self.artifacts / "watchdog.json").read_text())
        self.assertEqual(result["outcome"], "supervisor_error")
        self.assertTrue(result["cleanup"]["leader_reaped"])
        self.assertTrue(result["fail_closed"])
        self.assertFalse(result["output_complete"])
        self.assertIn("log storage unavailable", result["output_error"])

    def test_cleanup_drain_storage_failure_cannot_publish_native_success(self):
        attach = watchdog._OutputCapture.attach
        pump = watchdog._OutputCapture.pump
        first = True

        def attach_failing_sink(capture, process):
            attach(capture, process)
            process.wait(timeout=2)
            capture.sinks["stdout"] = mock.Mock()
            capture.sinks["stdout"].write.side_effect = OSError("cleanup log write failed")

        def skip_initial_read(capture, timeout):
            nonlocal first
            if first:
                first = False
                return
            pump(capture, timeout)

        with mock.patch.object(watchdog._OutputCapture, "attach", attach_failing_sink), \
                mock.patch.object(watchdog._OutputCapture, "pump", skip_initial_read):
            result = self.run_code("print('buffered output')")
        self.assertEqual(result["runtime_exit_code"], 0)
        self.assertEqual(result["outcome"], "supervisor_error")
        self.assertTrue(result["cleanup"]["leader_reaped"])
        self.assertIn("cleanup log write failed", result["cleanup"]["output_error"])
        self.assertTrue(result["fail_closed"])

    def test_cli_output_limit_is_enforced(self):
        binary = self.root / "fake-node"
        binary.write_text(f"#!{sys.executable}\nimport os\nos.write(1,b'x'*8192)\n")
        binary.chmod(0o700)
        completed = subprocess.run([sys.executable, str(SCRIPT), "--franken-node-bin", str(binary),
                                    "--artifacts-dir", str(self.artifacts), "--max-output-bytes", "64",
                                    "--", "app.js"], capture_output=True, text=True, timeout=5)
        self.assertEqual(completed.returncode, 125, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["outcome"], "output_limit_exceeded")
        self.assertEqual(result["max_output_bytes_per_stream"], 64)
        self.assertEqual((self.artifacts / "stdout.log").stat().st_size, 64)


    def test_default_stdin_remains_devnull(self):
        result = self.run_code("import os; assert os.read(0,1) == b''")
        self.assertEqual(result["outcome"], "completed")
        self.assertEqual(result["stdin_mode"], "null")
        self.assertEqual(result["stdin_delivery_state"], "not_requested")
        self.assertIsNone(result["stdin_sha256"])
        self.assertFalse((self.artifacts / "stdin.bin").exists())

    def test_empty_captured_stdin_delivers_pipe_eof(self):
        result = self.run_code("import os,stat; assert stat.S_ISFIFO(os.fstat(0).st_mode); "
                               "assert os.read(0,1) == b''", stdin_data=b"")
        self.assertEqual(result["outcome"], "completed")
        self.assertEqual(result["stdin_mode"], "pipe")
        self.assertEqual(result["stdin_sha256"], hashlib.sha256(b"").hexdigest())
        self.assertTrue(result["stdin_captured"])
        self.assertTrue(result["stdin_delivery_complete"])
        self.assertEqual((self.artifacts / "stdin.bin").read_bytes(), b"")

    @unittest.skipUnless(shutil.which("node"), "requires Node for executable stdin oracle")
    def test_real_node_receives_exact_binary_stdin(self):
        payload = bytes(range(256)) * 1024
        result = watchdog.supervise(
            [shutil.which("node"), "-e",
             "const fs=require('fs'); fs.writeFileSync(1,fs.readFileSync(0));"],
            self.artifacts, stdin_data=payload, max_stdin_bytes=len(payload),
            max_output_bytes=len(payload), wall_time_ms=3000, kill_grace_ms=100)
        self.assertEqual(result["outcome"], "completed")
        self.assertEqual((self.artifacts / "stdout.log").read_bytes(), payload)
        self.assertEqual((self.artifacts / "stdin.bin").read_bytes(), payload)
        self.assertEqual(result["stdin_sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(result["stdin_delivered_bytes"], len(payload))
        self.assertTrue(result["stdin_delivery_complete"])
        self.assertEqual((self.artifacts / "stdin.bin").stat().st_mode & 0o777, 0o600)

    def test_large_input_and_pre_read_output_do_not_deadlock(self):
        payload = bytes(range(256)) * 8192
        code = """
import os,sys
os.write(1,b'x'*1048576)
os.write(2,b'y'*1048576)
data=sys.stdin.buffer.read()
sys.stdout.buffer.write(data)
"""
        result = self.run_code(code, budget=4000, stdin_data=payload)
        self.assertEqual(result["outcome"], "completed")
        self.assertEqual((self.artifacts / "stdout.log").read_bytes(), b"x" * 1048576 + payload)
        self.assertEqual((self.artifacts / "stderr.log").read_bytes(), b"y" * 1048576)
        self.assertEqual(result["stdin_delivered_bytes"], len(payload))
        self.assertTrue(result["output_complete"])

    def test_nonreading_guest_still_times_out_with_captured_input(self):
        payload = b"request" * 200000
        result = self.run_code("import time; time.sleep(60)", budget=300, stdin_data=payload)
        self.assertEqual(result["outcome"], "wrapper_timeout")
        self.assertTrue(result["wrapper_deadline_exceeded"])
        self.assertLess(result["stdin_delivered_bytes"], len(payload))
        self.assertFalse(result["stdin_delivery_complete"])
        self.assertEqual(result["stdin_delivery_state"], "stopped")
        self.assertEqual((self.artifacts / "stdin.bin").read_bytes(), payload)
        self.assertTrue(result["cleanup"]["leader_reaped"])
        self.assertLess(result["elapsed_ms"], 1500)

    def test_cancelled_pending_input_retains_snapshot_and_stops_feeding(self):
        self.cancel_cli(signal.SIGTERM, repeat=True, stdin_data=b"pending" * 200000)

    def test_early_stdin_close_cannot_claim_full_request_delivery(self):
        result = self.run_code("import os,time; os.close(0); print('prefix-only'); time.sleep(.05)",
                               stdin_data=b"request" * 200000)
        self.assertEqual(result["runtime_exit_code"], 0)
        self.assertEqual(result["outcome"], "input_incomplete")
        self.assertEqual(result["wrapper_exit_code"], 125)
        self.assertEqual(result["stdin_delivery_state"], "closed_early")
        self.assertFalse(result["stdin_delivery_complete"])
        self.assertTrue(result["fail_closed"])
        self.assertTrue(result["output_complete"])
        self.assertEqual((self.artifacts / "stdout.log").read_bytes(), b"prefix-only\n")

    def test_native_failure_is_preserved_when_input_was_not_fully_delivered(self):
        result = self.run_code("raise SystemExit(7)", stdin_data=b"x" * 2000000)
        self.assertEqual(result["outcome"], "runtime_failed")
        self.assertEqual(result["runtime_exit_code"], 7)
        self.assertEqual(result["wrapper_exit_code"], 7)
        self.assertFalse(result["stdin_delivery_complete"])

    def test_invalid_or_oversized_input_cannot_create_artifacts_or_launch(self):
        for content in ("text", bytearray(b"mutable"), memoryview(b"view"), 1):
            with self.subTest(content=content), self.assertRaisesRegex(ValueError, "immutable bytes"):
                self.run_code("pass", stdin_data=content)
        with self.assertRaisesRegex(ValueError, "exceeds"):
            self.run_code("pass", stdin_data=b"four", max_stdin_bytes=3)
        with self.assertRaises(argparse.ArgumentTypeError):
            self.run_code("pass", stdin_data=b"", max_stdin_bytes=0)
        self.assertFalse(self.artifacts.exists())

    def test_stdin_snapshot_failure_prevents_launch(self):
        with mock.patch.object(watchdog, "_write_stdin_snapshot", side_effect=OSError("input disk failed")), \
                mock.patch.object(watchdog.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(OSError, "input disk"):
                self.run_code("pass", stdin_data=b"request")
            popen.assert_not_called()
        result = json.loads((self.artifacts / "watchdog.json").read_text())
        self.assertEqual(result["outcome"], "supervisor_error")
        self.assertFalse(result["stdin_captured"])
        self.assertTrue(result["fail_closed"])
        self.assertNotIn("runtime_pid", result)

    def test_expired_capture_budget_cannot_launch_guest(self):
        write = watchdog._write_stdin_snapshot

        def slow_snapshot(path, content):
            write(path, content)
            time.sleep(.1)

        with mock.patch.object(watchdog, "_write_stdin_snapshot", side_effect=slow_snapshot), \
                mock.patch.object(watchdog.subprocess, "Popen") as popen:
            result = self.run_code("pass", budget=30, stdin_data=b"request")
            popen.assert_not_called()
        self.assertEqual(result["outcome"], "wrapper_timeout")
        self.assertTrue(result["stdin_captured"])
        self.assertFalse(result["stdin_delivery_complete"])

    def test_stdin_transport_failure_stops_runtime_and_is_not_output_failure(self):
        with mock.patch.object(watchdog._InputFeed, "write_ready", side_effect=OSError("input pipe failed")):
            with self.assertRaisesRegex(OSError, "input pipe"):
                self.run_code("import time; time.sleep(60)", stdin_data=b"request")
        result = json.loads((self.artifacts / "watchdog.json").read_text())
        self.assertEqual(result["outcome"], "supervisor_error")
        self.assertIn("input pipe failed", result["stdin_error"])
        self.assertNotIn("output_error", result)
        self.assertTrue(result["cleanup"]["leader_reaped"])

    def test_stdin_file_rejects_symlink_fifo_device_and_oversize(self):
        source = self.root / "source.bin"
        source.write_bytes(b"four")
        alias = self.root / "alias.bin"
        alias.symlink_to(source)
        fifo = self.root / "request.fifo"
        os.mkfifo(fifo)
        for path in (alias, fifo, Path(os.devnull), self.root):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "regular file"):
                watchdog.read_stdin_file(path)
        with self.assertRaisesRegex(ValueError, "exceeds"):
            watchdog.read_stdin_file(source, 3)
        self.assertEqual(watchdog.read_stdin_file(source, 4), b"four")

    def test_stdin_file_rejects_replacement_between_stat_and_open(self):
        source = self.root / "request.bin"
        source.write_bytes(b"original")
        replacement = self.root / "replacement.bin"
        replacement.write_bytes(b"modified")
        opener = watchdog.os.open

        def replace_before_open(path, flags):
            os.replace(replacement, source)
            return opener(path, flags)

        with mock.patch.object(watchdog.os, "open", side_effect=replace_before_open):
            with self.assertRaisesRegex(ValueError, "changed before"):
                watchdog.read_stdin_file(source)

    def test_stdin_file_rejects_in_place_changes_during_capture(self):
        source = self.root / "request.bin"
        source.write_bytes(b"original")
        fstat = watchdog.os.fstat
        calls = 0

        def change_before_final_stat(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                source.write_bytes(b"changed source size")
            return fstat(fd)

        with mock.patch.object(watchdog.os, "fstat", side_effect=change_before_final_stat):
            with self.assertRaisesRegex(ValueError, "changed during"):
                watchdog.read_stdin_file(source)

    def test_captured_bytes_are_used_after_original_source_is_replaced(self):
        source = self.root / "request.bin"
        source.write_bytes(b"captured\x00\xff")
        content = watchdog.read_stdin_file(source)
        source.write_bytes(b"different request")
        result = self.run_code("import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())", stdin_data=content)
        self.assertEqual(result["outcome"], "completed")
        self.assertEqual((self.artifacts / "stdout.log").read_bytes(), b"captured\x00\xff")
        self.assertEqual((self.artifacts / "stdin.bin").read_bytes(), content)

    def test_cli_captures_stdin_before_changing_child_cwd(self):
        binary = self.root / "fake-node"
        binary.write_text(f"#!{sys.executable}\nimport sys\nsys.stdout.buffer.write(sys.stdin.buffer.read())\n")
        binary.chmod(0o700)
        source = self.root / "request.bin"
        source.write_bytes(b"request\x00\xff")
        child_dir = self.root / "child"
        child_dir.mkdir()
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--franken-node-bin", str(binary),
             "--artifacts-dir", str(self.artifacts), "--stdin-file", "request.bin",
             "--cwd", str(child_dir), "--", "app.js"], cwd=self.root,
            capture_output=True, text=True, timeout=5)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["cwd"], str(child_dir))
        self.assertTrue(result["stdin_delivery_complete"])
        self.assertEqual((self.artifacts / "stdin.bin").read_bytes(), source.read_bytes())
        self.assertEqual((self.artifacts / "stdout.log").read_bytes(), source.read_bytes())

    def test_cli_refuses_oversize_stdin_before_launch(self):
        source = self.root / "request.bin"
        source.write_bytes(b"too big")
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--artifacts-dir", str(self.artifacts),
             "--stdin-file", str(source), "--max-stdin-bytes", "2", "--", "app.js"],
            capture_output=True, text=True, timeout=5)
        self.assertEqual(completed.returncode, 125)
        self.assertIn("exceeds", completed.stderr)
        self.assertFalse(self.artifacts.exists())


if __name__ == "__main__":
    unittest.main()
