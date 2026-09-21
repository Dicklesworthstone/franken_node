"""Native CLI integration contracts; parser-only evidence is explicitly labeled.

The optional probe is compiled from the production cli.rs by runtime-watchdog.yml.
All generic supervision, quota and signal regressions remain in the original suite.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "runtime_invoke_watchdog.py"
spec = importlib.util.spec_from_file_location("watchdog_native_cli", SCRIPT)
watchdog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watchdog)
PROBE = os.environ.get("FRANKEN_NODE_WATCHDOG_CLI_PROBE")


class NativeRunCommandTests(unittest.TestCase):
    def test_valid_arguments_are_preserved_without_policy_downgrade(self):
        args = ["entry point.js", "--policy", "strict", "--config", "config/safe.toml",
                "--runtime", "franken-engine", "--console-only", "--trace-id", "trace-1"]
        command = watchdog.native_run_command("/opt/franken-node", args)
        self.assertEqual(command, ["/opt/franken-node", "run", *args])
        self.assertEqual(args[0], "entry point.js")
        self.assertNotIn("--output-dir", command)

    def test_json_output_is_not_forced_into_console_only(self):
        self.assertEqual(watchdog.native_run_command("node", ["app.js", "--json"]),
                         ["node", "run", "app.js", "--json"])

    def test_nonexistent_old_interface_flags_are_rejected(self):
        for flag in ("--output-dir", "--execution-budget-ms", "--execution-budget-ticks"):
            for value in ([flag, "10"], [flag + "=10"]):
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, "not a franken-node run option"):
                    watchdog.native_run_command("node", ["app.js", *value])

    def test_no_command_string_or_nul_is_interpreted(self):
        for args in ([], "app.js; touch nope", ["bad\x00arg"], [1]):
            with self.subTest(args=args), self.assertRaises(ValueError):
                watchdog.native_run_command("node", args)
        self.assertEqual(watchdog.native_run_command("node", ["name;echo surprise.js"]),
                         ["node", "run", "name;echo surprise.js"])

    def test_invalid_old_arguments_create_no_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            artifacts = Path(temp) / "evidence"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--artifacts-dir", str(artifacts),
                 "--", "app.js", "--execution-budget-ms=10"],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertIn("--wall-time-ms before --", result.stderr)
            self.assertFalse(artifacts.exists())


@unittest.skipUnless(PROBE and os.name == "posix", "requires the compiled production CLI parser probe")
class ProductionCliParserTests(unittest.TestCase):
    def invoke(self, arguments):
        with tempfile.TemporaryDirectory() as temp:
            artifacts = Path(temp) / "evidence"
            process = subprocess.run(
                [sys.executable, str(SCRIPT), "--franken-node-bin", PROBE,
                 "--artifacts-dir", str(artifacts), "--", *arguments],
                capture_output=True, text=True, timeout=10)
            receipt = json.loads(process.stdout)
            stdout = (artifacts / "stdout.log").read_text()
            stderr = (artifacts / "stderr.log").read_text()
            self.assertEqual(receipt, json.loads((artifacts / "watchdog.json").read_text()))
            self.assertIsNone(receipt["native_receipts_dir"])
            return process, receipt, stdout, stderr

    def test_real_parser_accepts_policy_governed_command(self):
        process, receipt, stdout, stderr = self.invoke(
            ["entry point.js", "--policy", "strict", "--config", "safe.toml",
             "--runtime", "franken-engine", "--console-only", "--trace-id", "check-1"])
        self.assertEqual(process.returncode, 0, stderr)
        self.assertEqual(receipt["outcome"], "completed")
        parsed = json.loads(stdout)
        self.assertEqual(parsed["probe_kind"], "product_cli_parser_only")
        self.assertEqual(parsed["command"], "run")
        self.assertEqual(parsed["app_path"], "entry point.js")
        self.assertEqual(parsed["policy"], "strict")
        self.assertEqual(parsed["config"], "safe.toml")
        self.assertEqual(parsed["runtime"], "franken-engine")
        self.assertEqual(parsed["trace_id"], "check-1")
        self.assertTrue(parsed["console_only"])
        self.assertFalse(parsed["json"])

    def test_native_json_and_engine_binary_options_reach_parser(self):
        process, _, stdout, stderr = self.invoke(
            ["app.js", "--json", "--engine-bin", "/opt/franken-engine"])
        self.assertEqual(process.returncode, 0, stderr)
        parsed = json.loads(stdout)
        self.assertTrue(parsed["json"])
        self.assertFalse(parsed["console_only"])
        self.assertEqual(parsed["engine_bin"], "/opt/franken-engine")

    def test_actual_native_path_validation_is_not_bypassed(self):
        process, receipt, _, stderr = self.invoke(["../outside.js"])
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(receipt["outcome"], "runtime_failed")
        self.assertFalse(receipt["wrapper_deadline_exceeded"])
        self.assertIn("traversal", stderr.lower())

    def test_conflicting_output_modes_fail_in_actual_clap(self):
        process, receipt, _, _ = self.invoke(["app.js", "--json", "--console-only"])
        self.assertEqual(process.returncode, 2)
        self.assertEqual(receipt["outcome"], "runtime_failed")

    def test_probe_rejects_old_nonexistent_runtime_invoke_command(self):
        process = subprocess.run([PROBE, "runtime", "invoke", "app.js"],
                                 capture_output=True, text=True, timeout=5)
        self.assertEqual(process.returncode, 2)
        self.assertIn("invoke", process.stderr)


if __name__ == "__main__":
    unittest.main()
