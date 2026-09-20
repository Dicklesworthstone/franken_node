"""Executable watchdog tests; no Rust toolchain or sibling repos required."""
import argparse
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

    def run_code(self, code, budget=2000):
        return watchdog.supervise([sys.executable, "-u", "-c", code], self.artifacts,
                                  wall_time_ms=budget, kill_grace_ms=100)

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

    def test_large_output_does_not_block_or_require_pipes(self):
        result = self.run_code("import os; os.write(1,b'x'*2000000); os.write(2,b'y'*2000000)")
        self.assertEqual(result["outcome"], "completed")
        self.assertEqual(result["stdout_bytes"], 2000000)
        self.assertEqual(result["stderr_bytes"], 2000000)

    def test_cli_invokes_native_runtime_and_owns_receipts(self):
        binary = self.root / "fake node"
        binary.write_text(f"#!{sys.executable}\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n")
        binary.chmod(0o700)
        completed = subprocess.run([sys.executable, str(SCRIPT), "--franken-node-bin", str(binary),
                                    "--artifacts-dir", str(self.artifacts), "--", "entry point.js",
                                    "--execution-budget-ms", "10"], capture_output=True, text=True, timeout=5)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        received = json.loads((self.artifacts / "stdout.log").read_text())
        self.assertEqual(received[:4], ["runtime", "invoke", "--output-dir", str(self.artifacts / "runtime")])
        self.assertEqual(received[4:], ["entry point.js", "--execution-budget-ms", "10"])
        self.assertEqual(result["outcome"], "completed")

    def test_cli_rejects_output_override(self):
        completed = subprocess.run([sys.executable, str(SCRIPT), "--artifacts-dir", str(self.artifacts),
                                    "--", "app.js", "--output-dir=/tmp/other"], capture_output=True, timeout=5)
        self.assertEqual(completed.returncode, 2)
        self.assertFalse(self.artifacts.exists())


if __name__ == "__main__":
    unittest.main()
