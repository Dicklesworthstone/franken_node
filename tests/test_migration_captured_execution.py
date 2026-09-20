"""Real process regressions for captured migration harness inputs.

Node/Node and Python/Python invocations below exercise the orchestrator. They
are explicit test executables, not evidence of native Franken compatibility.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts/migration_validation_runner.py"
SPEC = importlib.util.spec_from_file_location("captured_execution_runner", SOURCE)
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)
NODE = shutil.which("node")


class CapturedExecutionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="captured-execution-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def put(self, path, data, root=None):
        target = (root or self.root) / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data.encode() if isinstance(data, str) else data)
        return target

    def manifest(self, tests=("scripts/check.js",), execution=None, root=None):
        contents = {"schema_version": runner.MIGRATION_TEST_SCHEMA, "tests": list(tests)}
        if execution is not None:
            contents["execution"] = execution
        return self.put(runner.MIGRATION_TEST_MANIFEST, json.dumps(contents), root)

    def capture(self, root=None):
        return runner.capture_project(root or self.root, time.monotonic() + 10)[0]

    def inventory(self, root=None):
        return runner.captured_test_inventory(self.capture(root))

    def validate(self, root=None, **kwargs):
        executable = kwargs.pop("executable", sys.executable)
        return runner.validate_project(root or self.root,
            baseline_command=[executable, "{test}"], migration_command=[executable, "{test}"],
            **kwargs)

    def test_explicit_manifest_selects_sorted_harnesses_not_helpers(self):
        for name in ["scripts/z.mts", "scripts/a.cts", "test/helper.js", "node_modules/pkg/vendor.test.js"]:
            self.put(name, "// source")
        self.manifest(["scripts/z.mts", "scripts/a.cts"])
        self.assertEqual(list(self.inventory()), ["scripts/a.cts", "scripts/z.mts"])
        self.assertEqual(runner.discover_tests(self.root), [self.root / "scripts/a.cts", self.root / "scripts/z.mts"])

    def test_implicit_inventory_covers_all_native_extensions_and_excludes_state(self):
        for name in ["a.test.mts", "b.spec.cts", "test/one.mjs", "__tests__/nested/t.cjs",
                     ".franken-node/bad.test.js", ".migrate-backup/bad.test.js", "node_modules/bad.test.js"]:
            self.put(name, "// source")
        self.assertEqual(list(self.inventory()), ["__tests__/nested/t.cjs", "a.test.mts", "b.spec.cts", "test/one.mjs"])

    def test_invalid_manifest_never_falls_back_to_a_passing_heuristic(self):
        self.put("ok.test.js", "print('should not run')")
        for raw in ["{", "null", "[]", "{}", '{"schema_version":"unknown","tests":["ok.test.js"]}',
                    '{"schema_version":"franken-node/migration-tests/v1","tests":[]}',
                    '{"schema_version":"franken-node/migration-tests/v1","tests":["ok.test.js"],"ignore_failures":true}',
                    '{"schema_version":"franken-node/migration-tests/v1","tests":["ok.test.js"],"tests":[]}',
                    '{"schema_version":"franken-node/migration-tests/v1","tests":["ok.test.js"],"execution":NaN}',
                    '[' * 1000 + ']' * 1000]:
            with self.subTest(raw=raw[:80]):
                self.put(runner.MIGRATION_TEST_MANIFEST, raw)
                with patch.object(runner, "run_command", side_effect=AssertionError("must not execute")):
                    result = self.validate()
                self.assertEqual(result["summary"]["verdict"], "ERROR")
                self.assertEqual(result["validation_results"], [])

    def test_invalid_paths_and_missing_or_duplicate_entrypoints_fail(self):
        self.put("scripts/check.js", "print('ok')")
        for name in ["", "../check.js", "/check.js", "./scripts/check.js", "scripts//check.js",
                     "scripts/../scripts/check.js", "scripts/check.js/", "scripts\\check.js",
                     "scripts/check\n.js", "missing.js", "scripts/no.txt", "x" * 4097,
                     "\ud800.js"]:
            with self.subTest(name=repr(name)):
                self.manifest([name])
                with self.assertRaises(ValueError):
                    self.inventory()
        self.manifest(["scripts/check.js"] * 2)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.inventory()

    def test_manifest_and_configuration_links_fail_closed(self):
        self.put("scripts/check.js", "print('ok')")
        self.put("settings/migration-tests.json", json.dumps({"schema_version": runner.MIGRATION_TEST_SCHEMA,
                                                             "tests": ["scripts/check.js"]}))
        (self.root / ".franken-node").symlink_to("settings", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "configuration directory"):
            self.inventory()

    def test_linked_entrypoint_or_stdin_or_cwd_is_not_an_ordinary_capture(self):
        self.put("scripts/check.js", "print('ok')")
        (self.root / "scripts/alias.js").symlink_to("check.js")
        self.manifest(["scripts/alias.js"])
        with self.assertRaises(ValueError):
            self.inventory()
        (self.root / "alias").symlink_to("scripts", target_is_directory=True)
        for settings in [{"stdin": "scripts/alias.js"}, {"cwd": "alias"}]:
            self.manifest(execution={"scripts/check.js": settings})
            with self.assertRaises(ValueError):
                self.inventory()

    def test_unknown_execution_fields_tests_and_noncanonical_keys_fail(self):
        self.put("scripts/check.js", "print('ok')")
        for execution in [{"unknown.js": {}}, {"scripts/./check.js": {}},
                          {"scripts/check.js": {"command": "danger"}},
                          {"scripts/check.js": {"timeout": 3600}},
                          {"scripts/check.js": {"args": ["--eval", "bad"]}},
                          {"scripts/check.js": []}, []]:
            self.manifest(execution=execution)
            with self.assertRaises(ValueError):
                self.inventory()

    def test_duplicate_execution_and_environment_fields_are_rejected(self):
        self.put("scripts/check.js", "print('ok')")
        for execution in ['{"scripts/check.js":{},"scripts/check.js":{}}',
                          '{"scripts/check.js":{"cwd":"scripts","cwd":"."}}',
                          '{"scripts/check.js":{"environment":{"APP":"one","APP":"two"}}}']:
            self.put(runner.MIGRATION_TEST_MANIFEST,
                     '{"schema_version":"' + runner.MIGRATION_TEST_SCHEMA + '","tests":["scripts/check.js"],"execution":' + execution + '}')
            with self.assertRaises(ValueError):
                self.inventory()

    def test_cwd_requires_a_captured_ancestor_of_the_test(self):
        self.put("scripts/check.js", "print('ok')")
        self.put("fixtures/input", "input")
        for value in ["fixtures", "missing", "../outside", "./scripts", "scripts/check.js", "", 1, False]:
            self.manifest(execution={"scripts/check.js": {"cwd": value}})
            with self.assertRaises(ValueError):
                self.inventory()
        self.manifest(execution={"scripts/check.js": {"cwd": "."}})
        self.assertEqual(self.inventory()["scripts/check.js"], runner.ExecutionSettings())

    def test_manifest_stdin_and_test_inventory_limits(self):
        self.put(runner.MIGRATION_TEST_MANIFEST, b" " * (runner.MAX_MANIFEST_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "64 KiB"):
            self.inventory()
        self.put("scripts/check.js", "print('ok')")
        self.manifest(["scripts/check.js"] * (runner.MAX_TEST_FILES + 1))
        with self.assertRaises(ValueError):
            self.inventory()
        self.put("input", b"x" * (runner.MAX_INPUT_BYTES + 1))
        self.manifest(execution={"scripts/check.js": {"stdin": "input"}})
        with self.assertRaisesRegex(ValueError, "1 MiB"):
            self.inventory()

    def test_runtime_and_operator_environment_controls_cannot_be_overridden(self):
        self.put("scripts/check.js", "print('ok')")
        for name in ["NODE_OPTIONS", "BUN_OPTIONS", "PATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "HOME",
                     "FRANKEN_NODE_ALLOW_DEGRADED_RUNTIME_FALLBACK", "FRANKEN_NODE_MIGRATION_FAILURE_DIR",
                     "RUST_LOG", "BASH_ENV", "", "1NAME", "NAME=VALUE", "node_options"]:
            with self.subTest(name=name):
                self.manifest(execution={"scripts/check.js": {"environment": {name: "private-value"}}})
                with self.assertRaises(ValueError) as error:
                    self.inventory()
                self.assertNotIn("private-value", str(error.exception))

    def test_environment_bounds_types_unicode_and_redacted_debug(self):
        self.put("scripts/check.js", "print('ok')")
        for environment in [{"APP": "x" * 4097}, {"APP": "é" * 2049}, {"APP": "x\0y"},
                            {"APP": 1}, {"APP": "\ud800"}, {f"APP_{i}": None for i in range(65)},
                            {f"APP_{i}": "x" * 4096 for i in range(5)}, []]:
            self.manifest(execution={"scripts/check.js": {"environment": environment}})
            with self.assertRaises(ValueError):
                self.inventory()
        self.manifest(execution={"scripts/check.js": {"environment": {"APP_SECRET": "private-value", "NODE_ENV": "test", "DROP": None}}})
        settings = self.inventory()["scripts/check.js"]
        self.assertNotIn("private-value", repr(settings))
        self.assertEqual(len(settings.environment), 3)

    def test_captured_inventory_survives_later_live_source_changes(self):
        self.put("scripts/check.js", "print('captured')")
        self.put("input", b"captured")
        self.manifest(execution={"scripts/check.js": {"stdin": "input"}})
        capture = self.capture()
        self.manifest(["missing.js"])
        self.put("input", b"later")
        inventory = runner.captured_test_inventory(capture)
        self.assertEqual(list(inventory), ["scripts/check.js"])
        self.assertEqual(runner._test_input(inventory["scripts/check.js"], {e.path: e for e in capture}), b"captured")

    def test_candidate_cannot_substitute_settings_or_stdin_before_runtime_resolution(self):
        before, after = self.root / "before", self.root / "after"
        before.mkdir(); after.mkdir()
        for root in [before, after]:
            self.put("scripts/check.js", "print('same')", root)
            self.put("input", "original", root)
            self.manifest(execution={"scripts/check.js": {"stdin": "input"}}, root=root)
        for change in ["settings", "stdin"]:
            if change == "settings":
                self.manifest(execution={"scripts/check.js": {"stdin": "input", "environment": {"APP": "different"}}}, root=after)
            else:
                self.manifest(execution={"scripts/check.js": {"stdin": "input"}}, root=after)
                self.put("input", "different", after)
            with patch.object(runner, "resolve_command", side_effect=AssertionError("must not resolve runtimes")):
                report = self.validate(before, migrated_project=after)
            self.assertEqual(report["summary"]["verdict"], "ERROR")
            self.assertEqual(report["validation_results"], [])

    @unittest.skipUnless(NODE, "real Node executable required")
    def test_real_node_receives_captured_binary_stdin_cwd_env_and_records_root_effects(self):
        self.put("packages/api/check.cjs", "const fs=require('fs');process.stdout.write(fs.readFileSync(0));console.log(process.env.APP_MODE,fs.readFileSync('local.txt','utf8'),process.env.DROP_ME===undefined);fs.writeFileSync('artifact','ok');")
        self.put("packages/api/local.txt", "package-local")
        data = b"\0\xffx\n"
        self.put("fixtures/input.bin", data)
        self.manifest(["packages/api/check.cjs"], {"packages/api/check.cjs": {
            "cwd": "packages/api", "stdin": "fixtures/input.bin", "environment": {"APP_MODE": "captured", "DROP_ME": None}}})
        with patch.dict(os.environ, {"DROP_ME": "ambient"}):
            report = self.validate(executable=NODE, compare_filesystem=True)
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        row = report["validation_results"][0]
        expected = data + b"captured package-local true\n"
        for role in ["baseline", "migration"]:
            self.assertEqual(row[role]["streams"]["stdout"]["sha256"], hashlib.sha256(expected).hexdigest())
            self.assertEqual(list(row[role]["workspace_delta"]["changes"]), ["packages/api/artifact"])
        self.assertFalse((self.root / "packages/api/artifact").exists())
        self.assertFalse(report["release_certification"])

    def test_fresh_case_environment_does_not_leak_to_another_case_or_parent(self):
        source = "import os,sys\nprint(os.getenv('APP_MODE'),os.getenv('DROP'),len(sys.stdin.buffer.read()))\n"
        self.put("scripts/a.js", source); self.put("scripts/b.js", source)
        self.manifest(["scripts/a.js", "scripts/b.js"], {"scripts/a.js": {"environment": {"APP_MODE": "case", "DROP": None}}})
        with patch.dict(os.environ, {"APP_MODE": "ambient", "DROP": "retained"}):
            report = self.validate()
            self.assertEqual(os.environ["APP_MODE"], "ambient")
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        for row, expected in zip(report["validation_results"], [b"case None 0\n", b"ambient retained 0\n"]):
            self.assertEqual(row["baseline"]["streams"]["stdout"]["sha256"], hashlib.sha256(expected).hexdigest())

    def test_fallback_and_capture_directory_are_never_forwarded(self):
        self.put("case.test.js", "import os\nassert 'FRANKEN_NODE_ALLOW_DEGRADED_RUNTIME_FALLBACK' not in os.environ\nassert 'FRANKEN_NODE_MIGRATION_FAILURE_DIR' not in os.environ\nprint('clean')\n")
        with patch.dict(os.environ, {runner.PRIVATE_RUNTIME_VARIABLES[0]: "1", runner.PRIVATE_RUNTIME_VARIABLES[1]: "/private"}):
            report = self.validate()
        self.assertEqual(report["summary"]["verdict"], "PASS", report)

    def test_binary_stdin_and_output_are_drained_concurrently(self):
        data = bytes(range(256)) * 4096  # full 1 MiB input
        source = "import sys\nsys.stdout.buffer.write(b'o'*200000);sys.stdout.flush()\nsys.stderr.buffer.write(b'e'*200000);sys.stderr.flush()\nsys.stdout.buffer.write(sys.stdin.buffer.read())\n"
        self.put("scripts/check.js", source); self.put("input", data)
        self.manifest(execution={"scripts/check.js": {"stdin": "input"}})
        report = self.validate(timeout_seconds=5, max_output_bytes=2*1024*1024)
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        output = report["validation_results"][0]["baseline"]["streams"]["stdout"]
        self.assertEqual(output["sha256"], hashlib.sha256(b"o"*200000 + data).hexdigest())
        self.assertTrue(output["complete"])

    def test_empty_configured_stdin_delivers_eof(self):
        self.put("scripts/check.js", "import sys\nprint(len(sys.stdin.buffer.read()))\n")
        self.put("empty", b"")
        self.manifest(execution={"scripts/check.js": {"stdin": "empty"}})
        report = self.validate(timeout_seconds=2)
        self.assertEqual(report["summary"]["verdict"], "PASS", report)

    def test_child_that_never_reads_stdin_cannot_block_timeout(self):
        self.put("scripts/check.js", "import time\ntime.sleep(30)\n")
        self.put("input", b"x"*runner.MAX_INPUT_BYTES)
        self.manifest(execution={"scripts/check.js": {"stdin": "input"}})
        start = time.monotonic()
        report = self.validate(timeout_seconds=0.15)
        self.assertLess(time.monotonic()-start, 3)
        self.assertEqual(report["summary"]["verdict"], "FAIL", report)
        for role in ["baseline", "migration"]:
            self.assertEqual(report["validation_results"][0][role]["termination"], "timeout")

    def test_child_closing_input_early_is_reaped_without_hanging(self):
        self.put("scripts/check.js", "import os\nos.close(0)\nprint('done')\n")
        self.put("input", b"x"*runner.MAX_INPUT_BYTES)
        self.manifest(execution={"scripts/check.js": {"stdin": "input"}})
        report = self.validate(timeout_seconds=2)
        self.assertEqual(report["summary"]["verdict"], "PASS", report)

    def test_equal_nonzero_exit_and_equal_truncated_output_never_pass(self):
        self.manifest()
        for source, expected in [("raise SystemExit(7)\n", "exited"), ("print('x'*100000)\n", "output_limit")]:
            self.put("scripts/check.js", source)
            report = self.validate(max_output_bytes=100)
            self.assertEqual(report["summary"]["verdict"], "FAIL", report)
            self.assertEqual(report["validation_results"][0]["baseline"]["termination"], expected)

    def test_no_test_suite_and_mismatched_inventory_cannot_pass(self):
        self.put("index.js", "print('app')")
        self.assertEqual(self.validate()["summary"]["verdict"], "NO_TESTS")
        other = self.root / "other"
        other.mkdir()
        self.put("a.test.js", "print('a')", other)
        report = self.validate(other, migrated_project=self.root)
        self.assertNotEqual(report["summary"]["verdict"], "PASS")

    def test_only_declared_files_are_executed_no_package_install_or_shell(self):
        self.put("scripts/check.js", "print('ok')")
        self.put("test/helper.js", "raise SystemExit(91)")
        self.put("package.json", '{"scripts":{"test":"false"}}')
        self.manifest()
        report = self.validate()
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        self.assertEqual(report["summary"]["total_tests"], 1)


if __name__ == "__main__":
    unittest.main()
