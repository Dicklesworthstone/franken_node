"""Captured argv must reach real processes without becoming runtime options.

Python/Python and Node/Node pairs test the runner's execution contract, not
independent Node/Franken compatibility. No fake branded runtime is installed.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import migration_validation_runner as runner


PYTHON_COMMAND = (sys.executable, "{test}", "{arguments}")
LITERAL_ARGUMENTS = [
    "", "two words", "line\nbreak", "雪", "--policy", "legacy-risky", "--eval",
    "{test}", "{arguments}", "$(touch should-not-exist)", "a;echo shell", "--",
]


class ApplicationArgumentsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="migration-argv-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.project = self.root / "project"
        self.project.mkdir()

    def write_manifest(self, project=None, *, tests=None, execution=None):
        project = project or self.project
        directory = project / ".franken-node"
        directory.mkdir(exist_ok=True)
        manifest = {"schema_version": runner.MIGRATION_TEST_SCHEMA,
                    "tests": tests or ["probe.cjs"], "execution": execution or {}}
        (directory / "migration-tests.json").write_text(json.dumps(manifest), encoding="utf-8")

    def inventory(self, project=None):
        capture, _ = runner.capture_project(project or self.project, time.monotonic() + 10)
        return runner.captured_test_inventory(capture)

    def validate(self, **kwargs):
        return runner.validate_project(
            self.project, baseline_command=kwargs.pop("baseline_command", PYTHON_COMMAND),
            migration_command=kwargs.pop("migration_command", PYTHON_COMMAND),
            timeout_seconds=5, total_timeout_seconds=30, **kwargs)

    def test_manifest_preserves_literal_values_and_redacts_debug(self):
        (self.project / "probe.cjs").write_text("print('ok')\n")
        secret = "argument-secret-do-not-format"
        arguments = [*LITERAL_ARGUMENTS, secret]
        self.write_manifest(execution={"probe.cjs": {"arguments": arguments,
                                                    "environment": {"APP_SECRET": secret}}})
        settings = self.inventory()["probe.cjs"]
        self.assertEqual(settings.arguments, tuple(arguments))
        self.assertNotIn(secret, repr(settings))
        self.assertIn(f"argument_count={len(arguments)}", repr(settings))

    def test_invalid_arguments_are_not_coerced_or_echoed(self):
        secret = "argument-secret-do-not-format"
        invalid = [None, True, 3, secret, {}, [secret, None], [True], [7], [[secret]],
                   [secret + "\0"], ["\ud800"], [secret * 400], [""] * 129,
                   ["x" * 4096] * 8, ["雪" * 1366]]
        for value in invalid:
            with self.subTest(kind=type(value).__name__):
                with self.assertRaises(ValueError) as error:
                    runner._literal_arguments(value)
                self.assertNotIn(secret, str(error.exception))

    def test_argument_limits_count_utf8_and_os_terminators(self):
        for value in [[], [""] * 128, ["x" * 4096], ["雪" * 1365], ["x" * 4095] * 8]:
            self.assertEqual(runner._literal_arguments(value), tuple(value))
        with self.assertRaises(ValueError):
            runner._literal_arguments(["x" * 4095] * 8 + [""])

    def test_unknown_args_alias_and_duplicate_keys_remain_errors(self):
        (self.project / "probe.cjs").write_text("print('ok')\n")
        self.write_manifest(execution={"probe.cjs": {"args": ["not-an-alias"]}})
        with self.assertRaises(ValueError):
            self.inventory()
        (self.project / runner.MIGRATION_TEST_MANIFEST).write_text(
            '{"schema_version":"franken-node/migration-tests/v1","tests":["probe.cjs"],'
            '"execution":{"probe.cjs":{"arguments":[],"arguments":["secret"]}}}')
        with self.assertRaises(ValueError):
            self.inventory()

    def test_template_slot_is_single_standalone_terminal_and_after_script(self):
        invalid = [
            [sys.executable, "{arguments}", "{test}"],
            [sys.executable, "{test}", "{arguments}", "tail"],
            [sys.executable, "{test}", "{arguments}", "{arguments}"],
            [sys.executable, "{test}", "prefix={arguments}"],
            ["{arguments}", "{test}"],
        ]
        for command in invalid:
            with self.subTest(command=command), self.assertRaises(ValueError):
                runner.resolve_command(command)
        template = runner.resolve_command(PYTHON_COMMAND)
        self.assertEqual(runner._test_command(template, "probe.cjs", tuple(LITERAL_ARGUMENTS)),
                         [str(Path(sys.executable).resolve()), "./probe.cjs", *LITERAL_ARGUMENTS])

    def test_default_native_template_terminates_options_before_guest_flags(self):
        # Check the actual shipped templates without inventing a native binary.
        native = runner._test_command(list(runner.DEFAULT_MIGRATION_COMMAND), "probe.cjs",
                                      ("--policy", "legacy-risky", "--engine-bin", "untrusted"))
        self.assertEqual(native, ["franken-node", "run", "--console-only", "./probe.cjs", "--",
                                  "--policy", "legacy-risky", "--engine-bin", "untrusted"])
        node = runner._test_command(list(runner.DEFAULT_BASELINE_COMMAND), "probe.cjs", ("--eval", "x"))
        self.assertEqual(node, ["node", "./probe.cjs", "--eval", "x"])

    def test_real_processes_receive_argv_stdin_cwd_and_environment_together(self):
        directory = self.project / "pkg"
        directory.mkdir()
        payload = b"\0\xffrequest\r\n"
        (self.project / "request.bin").write_bytes(payload)
        source = ("import os, pathlib, sys\n"
                  f"assert sys.argv[1:] == {LITERAL_ARGUMENTS!r}\n"
                  "assert pathlib.Path.cwd().name == 'pkg'\n"
                  "assert os.environ['APP_MODE'] == 'migration'\n"
                  f"assert sys.stdin.buffer.read() == {payload!r}\n"
                  "assert not pathlib.Path('should-not-exist').exists()\n"
                  "print('literal argv verified')\n")
        (directory / "probe.cjs").write_text(source, encoding="utf-8")
        self.write_manifest(tests=["pkg/probe.cjs"], execution={"pkg/probe.cjs": {
            "arguments": LITERAL_ARGUMENTS, "cwd": "pkg", "stdin": "request.bin",
            "environment": {"APP_MODE": "migration"}}})
        report = self.validate(compare_filesystem=True)
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        expected = hashlib.sha256(b"literal argv verified\n").hexdigest()
        for role in ("baseline", "migration"):
            self.assertEqual(report["validation_results"][0][role]["streams"]["stdout"]["sha256"], expected)
        self.assertNotIn("$(touch", json.dumps(report))
        self.assertFalse((self.project / "pkg" / "should-not-exist").exists())

    @unittest.skipUnless(shutil.which("node"), "real Node executable unavailable")
    def test_real_node_observes_empty_unicode_and_option_looking_app_arguments(self):
        (self.project / "probe.cjs").write_text(
            "console.log(JSON.stringify(process.argv.slice(2)));\n", encoding="utf-8")
        self.write_manifest(execution={"probe.cjs": {"arguments": LITERAL_ARGUMENTS}})
        command = (shutil.which("node"), "{test}", "{arguments}")
        report = self.validate(baseline_command=command, migration_command=command)
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        expected = (json.dumps(LITERAL_ARGUMENTS, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
        observed = report["validation_results"][0]["baseline"]["streams"]["stdout"]
        self.assertEqual(observed["sha256"], hashlib.sha256(expected).hexdigest())
        self.assertTrue(observed["complete"])

    def test_changed_candidate_arguments_refuse_before_either_leg(self):
        candidate = self.root / "candidate"
        candidate.mkdir()
        for project, arguments in [(self.project, ["old"]), (candidate, ["new"])]:
            (project / "probe.cjs").write_text("print('must not execute')\n")
            self.write_manifest(project, execution={"probe.cjs": {"arguments": arguments}})
        with mock.patch.object(runner, "run_command") as launch:
            report = self.validate(migrated_project=candidate)
        launch.assert_not_called()
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertIn("settings differ", report["errors"][0]["message"])

    def test_later_test_missing_second_leg_slot_prevents_every_launch(self):
        for name in ("a.cjs", "z.cjs"):
            (self.project / name).write_text("print('must not execute')\n")
        self.write_manifest(tests=["a.cjs", "z.cjs"], execution={"z.cjs": {"arguments": ["later"]}})
        with mock.patch.object(runner, "run_command") as launch:
            report = self.validate(migration_command=(sys.executable, "{test}"))
        launch.assert_not_called()
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertIn("{arguments}", report["errors"][0]["message"])
        self.assertEqual(report["validation_results"], [])

    def test_combined_template_and_application_argv_bound_precedes_launch(self):
        (self.project / "probe.cjs").write_text("print('must not execute')\n")
        self.write_manifest(execution={"probe.cjs": {"arguments": ["x" * 4095] * 8}})
        template = (sys.executable, "--trusted-option=" + "a" * 34000, "{test}", "{arguments}")
        with mock.patch.object(runner, "run_command") as launch:
            report = self.validate(baseline_command=template)
        launch.assert_not_called()
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertIn("expanded runtime argv", report["errors"][0]["message"])

    def test_no_argument_legacy_template_remains_exact(self):
        (self.project / "probe.cjs").write_text("import sys\nassert sys.argv[1:] == []\nprint('ok')\n")
        self.write_manifest(execution={"probe.cjs": {"arguments": []}})
        command = (sys.executable, "{test}")
        report = self.validate(baseline_command=command, migration_command=command)
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        self.assertEqual(report["commands"]["baseline"][1:], ["{test}"])

    def test_bundle_reexecution_uses_captured_argv_after_original_project_moves(self):
        secret = "secret-cli-value-not-in-report"
        arguments = [*LITERAL_ARGUMENTS, secret]
        (self.project / "probe.cjs").write_text(
            f"import sys\nassert sys.argv[1:] == {arguments!r}\nprint('replayed argv')\n", encoding="utf-8")
        self.write_manifest(execution={"probe.cjs": {"arguments": arguments}})
        path = self.root / "capture.fnmigration"
        report = self.validate(bundle_path=path)
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        self.assertNotIn(secret, json.dumps(report))
        digest = report["replay_bundle"]["sha256"]
        bundle = runner.read_replay_bundle(path, expected_sha256=digest)
        self.assertEqual(runner.captured_test_inventory(bundle.snapshots["baseline"])["probe.cjs"].arguments,
                         tuple(arguments))
        self.project.rename(self.root / "original-unavailable")
        replay = runner.replay_captured_bundle(path, expected_sha256=digest,
                    baseline_command=PYTHON_COMMAND, migration_command=PYTHON_COMMAND)
        self.assertEqual(replay["replay_outcome"], "REPRODUCED", replay)
        self.assertNotIn(secret, json.dumps(replay))
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_replay_rejects_changed_argument_delivery_template_before_launch(self):
        (self.project / "probe.cjs").write_text("print('ok')\n")
        self.write_manifest(execution={"probe.cjs": {"arguments": ["secret"]}})
        path = self.root / "capture.fnmigration"
        report = self.validate(bundle_path=path)
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        with mock.patch.object(runner, "run_command") as launch:
            replay = runner.replay_captured_bundle(path,
                expected_sha256=report["replay_bundle"]["sha256"],
                baseline_command=(sys.executable, "{test}"), migration_command=PYTHON_COMMAND)
        launch.assert_not_called()
        self.assertEqual(replay["replay_outcome"], "ERROR")
        self.assertIn("command arguments differ", replay["errors"][0]["message"])


if __name__ == "__main__":
    unittest.main()
