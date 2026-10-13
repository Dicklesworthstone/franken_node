"""Independent captured output oracles for migration execution and replay.

Explicit Python/Python and Node/Node pairs exercise runner behavior. They do not
claim independent runtime compatibility, release certification, or sandboxing.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import migration_validation_runner as runner

COMMAND = (sys.executable, "{test}", "{arguments}")


class OutputExpectationsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="migration-expected-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.configure(self.project)

    def configure(self, project, *, expectations=None, source="print('expected')\n", execution=None):
        (project / "probe.cjs").write_text(source, encoding="utf-8")
        (project / "fixtures").mkdir(exist_ok=True)
        (project / "fixtures/stdout.bin").write_bytes(b"expected\n")
        (project / "fixtures/stderr.bin").write_bytes(b"")
        (project / ".franken-node").mkdir(exist_ok=True)
        self.manifest(project, expectations=expectations if expectations is not None else {
            "probe.cjs": {"stdout": "fixtures/stdout.bin", "stderr": "fixtures/stderr.bin"}}, execution=execution)

    def manifest(self, project=None, *, expectations, execution=None):
        project = project or self.project
        raw = {"schema_version": runner.MIGRATION_TEST_SCHEMA, "tests": ["probe.cjs"],
               "expectations": expectations, "execution": execution or {}}
        (project / runner.MIGRATION_TEST_MANIFEST).write_text(json.dumps(raw), encoding="utf-8")

    def inventory(self):
        entries, _ = runner.capture_project(self.project, time.monotonic() + 10)
        return runner.captured_test_inventory(entries)

    def validate(self, **kwargs):
        return runner.validate_project(self.project,
            baseline_command=kwargs.pop("baseline_command", COMMAND),
            migration_command=kwargs.pop("migration_command", COMMAND),
            timeout_seconds=kwargs.pop("timeout_seconds", 5), total_timeout_seconds=30, **kwargs)

    def reasons(self, report):
        return report["validation_results"][0]["divergences"]

    def test_both_correct_streams_and_generated_binary_file_pass(self):
        data = b"\0\xff\r\nprivate-data"
        (self.project / "fixtures/file.bin").write_bytes(data)
        (self.project / "fixtures/stderr.bin").write_bytes(b"warning\n")
        (self.project / "probe.cjs").write_text(
            "import pathlib, sys\nprint('expected')\n"
            "sys.stderr.write('warning\\n')\npathlib.Path('out').mkdir()\n"
            f"pathlib.Path('out/generated.bin').write_bytes({data!r})\n")
        self.manifest(expectations={"probe.cjs": {"stdout": "fixtures/stdout.bin",
            "stderr": "fixtures/stderr.bin", "files": {"out/generated.bin": "fixtures/file.bin"}}})
        result = self.validate()
        self.assertEqual(result["summary"]["verdict"], "PASS", result)
        self.assertFalse(result["filesystem_comparison"])
        self.assertEqual(self.reasons(result), [])
        self.assertNotIn("private-data", json.dumps(result))
        self.assertFalse((self.project / "out").exists())

    def test_identical_wrong_streams_fail_independently_without_revealing_bytes(self):
        (self.project / "probe.cjs").write_text("print('wrong-private-payload')\n")
        result = self.validate()
        self.assertEqual(result["summary"]["verdict"], "FAIL", result)
        self.assertEqual(self.reasons(result), [
            {"channel": "baseline", "stream": "stdout", "reason": "expected_output_mismatch"},
            {"channel": "migration", "stream": "stdout", "reason": "expected_output_mismatch"}])
        self.assertNotIn("wrong-private-payload", json.dumps(result))

    def test_identical_wrong_files_fail_even_when_workspace_deltas_agree(self):
        (self.project / "probe.cjs").write_text("from pathlib import Path\nPath('output').write_bytes(b'wrong')\n")
        self.manifest(expectations={"probe.cjs": {"files": {"output": "fixtures/stdout.bin"}}})
        result = self.validate(compare_filesystem=True)
        self.assertEqual(result["summary"]["verdict"], "FAIL", result)
        self.assertEqual([item["reason"] for item in self.reasons(result)], ["expected_file_mismatch"] * 2)
        row = result["validation_results"][0]
        self.assertEqual(row["baseline"]["workspace_delta"], row["migration"]["workspace_delta"])

    def test_only_incorrect_leg_gets_an_expectation_mismatch(self):
        candidate = self.root / "candidate"
        candidate.mkdir()
        self.configure(candidate, source="print('wrong')\n")
        result = self.validate(migrated_project=candidate)
        self.assertEqual(result["summary"]["verdict"], "FAIL", result)
        mismatches = [item for item in self.reasons(result) if item["reason"] == "expected_output_mismatch"]
        self.assertEqual(mismatches, [{"channel": "migration", "stream": "stdout",
                                      "reason": "expected_output_mismatch"}])
        self.assertIn({"channel": "stdout", "reason": "byte_mismatch"}, self.reasons(result))

    def test_candidate_fixture_change_is_rejected_before_execution(self):
        candidate = self.root / "candidate"
        candidate.mkdir()
        self.configure(candidate)
        (candidate / "fixtures/stdout.bin").write_bytes(b"new expected output\n")
        with mock.patch.object(runner, "run_command") as launch:
            result = self.validate(migrated_project=candidate)
        launch.assert_not_called()
        self.assertEqual(result["summary"]["verdict"], "ERROR")
        self.assertIn("expectation bytes differ", result["errors"][0]["message"])

    def test_candidate_cannot_remove_an_expectation(self):
        candidate = self.root / "candidate"
        candidate.mkdir()
        self.configure(candidate, expectations={})
        with mock.patch.object(runner, "run_command") as launch:
            result = self.validate(migrated_project=candidate)
        launch.assert_not_called()
        self.assertEqual(result["summary"]["verdict"], "ERROR")
        self.assertIn("settings differ", result["errors"][0]["message"])

    def test_guest_cannot_rewrite_its_captured_expected_output(self):
        (self.project / "probe.cjs").write_text(
            "from pathlib import Path\nPath('fixtures/stdout.bin').write_bytes(b'wrong\\n')\nprint('wrong')\n")
        result = self.validate()
        self.assertEqual(result["summary"]["verdict"], "FAIL", result)
        self.assertEqual(len(self.reasons(result)), 2)
        self.assertEqual((self.project / "fixtures/stdout.bin").read_bytes(), b"expected\n")

    def test_empty_binary_and_exact_one_mib_fixtures(self):
        for data in (b"", b"\0\xffbinary\r\n", b"x" * runner.MAX_EXPECTATION_BYTES):
            with self.subTest(length=len(data)):
                (self.project / "fixtures/stdout.bin").write_bytes(data)
                (self.project / "probe.cjs").write_text(
                    "import pathlib, sys\nsys.stdout.buffer.write(pathlib.Path('fixtures/stdout.bin').read_bytes())\n")
                result = self.validate()
                self.assertEqual(result["summary"]["verdict"], "PASS", result)

    def test_fixture_byte_limit_is_checked_before_launch(self):
        (self.project / "fixtures/stdout.bin").write_bytes(b"x" * (runner.MAX_EXPECTATION_BYTES + 1))
        with mock.patch.object(runner, "run_command") as launch:
            result = self.validate()
        launch.assert_not_called()
        self.assertEqual(result["summary"]["verdict"], "ERROR")
        self.assertIn("1 MiB", result["errors"][0]["message"])

    def test_invalid_and_unselected_expectations_fail_closed(self):
        invalid = [None, [], {"other.cjs": {"stdout": "fixtures/stdout.bin"}},
                   {"probe.cjs": {}}, {"probe.cjs": {"files": {}}},
                   {"probe.cjs": {"stdout": None}}, {"probe.cjs": {"stderr": 7}},
                   {"probe.cjs": {"stdout": "missing.bin"}}, {"probe.cjs": {"stdout": "fixtures"}},
                   {"probe.cjs": {"exit_code": 1}}, {"probe.cjs": {"stdout": "../secret"}},
                   {"probe.cjs": {"stdout": ".franken-node/migration-tests.json"}},
                   {"probe.cjs": {"stdout": "fixtures/./stdout.bin"}},
                   {"probe.cjs": {"files": []}}, {"probe.cjs": {"files": {"out": None}}},
                   {"probe.cjs": {"files": {"/absolute": "fixtures/stdout.bin"}}},
                   {"probe.cjs": {"files": {"node_modules/output": "fixtures/stdout.bin"}}},
                   {"probe.cjs": {"files": {f"out-{i}": "fixtures/stdout.bin" for i in range(65)}}}]
        for value in invalid:
            with self.subTest(value=value):
                self.manifest(expectations=value)
                with mock.patch.object(runner, "run_command") as launch:
                    result = self.validate()
                launch.assert_not_called()
                self.assertEqual(result["summary"]["verdict"], "ERROR")

    def test_64_file_expectations_are_admitted_and_omission_remains_comparison_only(self):
        self.manifest(expectations={"probe.cjs": {"files": {
            f"out-{index}": "fixtures/stdout.bin" for index in range(64)}}})
        self.assertEqual(len(self.inventory()["probe.cjs"].expectations.files), 64)
        self.manifest(expectations={})
        (self.project / "probe.cjs").write_text("print('same output, no independent assertion')\n")
        self.assertEqual(self.validate()["summary"]["verdict"], "PASS")

    def test_symlink_expectation_fixture_is_not_followed(self):
        (self.project / "fixtures/alias.bin").symlink_to("stdout.bin")
        self.manifest(expectations={"probe.cjs": {"stdout": "fixtures/alias.bin"}})
        with mock.patch.object(runner, "run_command") as launch:
            result = self.validate()
        launch.assert_not_called()
        self.assertEqual(result["summary"]["verdict"], "ERROR")

    def test_output_missing_directory_fifo_and_symlink_are_not_regular_evidence(self):
        sources = ["pass\n", "from pathlib import Path\nPath('output').mkdir()\n",
                   "import os\nos.mkfifo('output')\n",
                   "from pathlib import Path\nPath('output').symlink_to('fixtures/stdout.bin')\n",
                   "from pathlib import Path\nPath('out').symlink_to('fixtures', target_is_directory=True)\n"]
        for index, source in enumerate(sources):
            with self.subTest(kind=index):
                target = "out/stdout.bin" if index == 4 else "output"
                (self.project / "probe.cjs").write_text(source)
                self.manifest(expectations={"probe.cjs": {"files": {target: "fixtures/stdout.bin"}}})
                started = time.monotonic()
                result = self.validate()
                self.assertEqual(result["summary"]["verdict"], "FAIL", result)
                self.assertEqual([item["reason"] for item in self.reasons(result)], ["expected_file_mismatch"] * 2)
                self.assertLess(time.monotonic() - started, 10)

    def test_output_root_is_pinned_before_path_replacement_and_parent_links_fail(self):
        workspace = self.root / "workspace"
        workspace.mkdir()
        (workspace / "result").write_bytes(b"original")
        expected = runner.OutputExpectations(files=(("result", "fixtures/stdout.bin"),))
        descriptor = runner._pin_output_workspace(workspace, expected)
        self.addCleanup(os.close, descriptor)
        workspace.rename(self.root / "original-workspace")
        workspace.mkdir()
        (workspace / "result").write_bytes(b"replacement")
        self.assertTrue(runner._matches_output_file(descriptor, "result", b"original", time.monotonic() + 5, None))
        (self.root / "original-workspace/link").symlink_to(workspace, target_is_directory=True)
        with mock.patch.object(os, "read") as read, self.assertRaises(OSError):
            runner._matches_output_file(descriptor, "link/result", b"replacement", time.monotonic() + 5, None)
        read.assert_not_called()

    def test_file_observation_checks_deadline_and_cancellation(self):
        descriptor = os.open(self.project, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, descriptor)
        with self.assertRaises(TimeoutError):
            runner._matches_output_file(descriptor, "fixtures/stdout.bin", b"expected\n", 0, None)
        cancel = runner.CancellationState(signum=15)
        with self.assertRaises(runner.ExecutionCancelled):
            runner._matches_output_file(descriptor, "fixtures/stdout.bin", b"expected\n", time.monotonic() + 5, cancel)

    def test_matching_assertions_do_not_excuse_nonzero_exit(self):
        (self.project / "probe.cjs").write_text("import sys\nprint('expected')\nsys.exit(1)\n")
        result = self.validate()
        self.assertEqual(result["summary"]["verdict"], "FAIL", result)
        self.assertEqual([item["exit_code"] for item in self.reasons(result)], [1, 1])

    def test_matching_retained_prefix_does_not_excuse_output_limit(self):
        (self.project / "fixtures/stdout.bin").write_bytes(b"x" * 16)
        (self.project / "probe.cjs").write_text("import sys\nsys.stdout.write('x' * 100)\n")
        result = self.validate(max_output_bytes=16)
        self.assertEqual(result["summary"]["verdict"], "FAIL", result)
        self.assertEqual(sum(item["reason"] == "expected_output_mismatch" and item.get("stream") == "stdout"
                             for item in self.reasons(result)), 2)
        self.assertEqual(sum(item["reason"] == "output_limit" for item in self.reasons(result)), 2)

    def test_matching_empty_output_does_not_excuse_timeout(self):
        (self.project / "fixtures/stdout.bin").write_bytes(b"")
        (self.project / "probe.cjs").write_text("import time\ntime.sleep(10)\n")
        result = self.validate(timeout_seconds=0.1)
        self.assertEqual(result["summary"]["verdict"], "FAIL", result)
        self.assertEqual(sum(item["reason"] == "timeout" for item in self.reasons(result)), 2)

    def test_file_targets_are_workspace_relative_not_test_cwd_relative(self):
        (self.project / "pkg").mkdir()
        (self.project / "probe.cjs").rename(self.project / "pkg/probe.cjs")
        (self.project / "pkg/probe.cjs").write_text("from pathlib import Path\nPath('output').write_bytes(b'expected\\n')\n")
        raw = {"schema_version": runner.MIGRATION_TEST_SCHEMA, "tests": ["pkg/probe.cjs"],
               "execution": {"pkg/probe.cjs": {"cwd": "pkg"}}, "expectations": {
                   "pkg/probe.cjs": {"files": {"pkg/output": "fixtures/stdout.bin"}}}}
        (self.project / runner.MIGRATION_TEST_MANIFEST).write_text(json.dumps(raw))
        self.assertEqual(self.validate()["summary"]["verdict"], "PASS")

    def test_replay_retains_independent_assertions_after_project_moves(self):
        (self.project / "probe.cjs").write_text("print('same wrong output')\n")
        bundle = self.root / "failure.fnmigration"
        result = self.validate(bundle_path=bundle)
        self.assertEqual(result["summary"]["verdict"], "FAIL", result)
        digest = result["replay_bundle"]["sha256"]
        self.project.rename(self.root / "original-unavailable")
        replay = runner.replay_captured_bundle(bundle, expected_sha256=digest,
                    baseline_command=COMMAND, migration_command=COMMAND)
        self.assertEqual(replay["replay_outcome"], "REPRODUCED", replay)
        self.assertEqual(replay["execution"]["summary"]["verdict"], "FAIL")
        self.assertEqual(self.reasons(replay["execution"]), self.reasons(result))
        self.assertEqual(hashlib.sha256(bundle.read_bytes()).hexdigest(), digest)

    @unittest.skipUnless(shutil.which("node"), "real Node executable unavailable")
    def test_real_node_checks_captured_args_and_independent_outputs(self):
        (self.project / "probe.cjs").write_text(
            "const fs = require('fs');\nconst data = process.argv[2];\n"
            "process.stdout.write(data);\nfs.writeFileSync('output', data);\n")
        data = "unicode 雪 literal --policy"
        (self.project / "fixtures/stdout.bin").write_bytes(data.encode())
        self.manifest(execution={"probe.cjs": {"arguments": [data]}}, expectations={"probe.cjs": {
            "stdout": "fixtures/stdout.bin", "stderr": "fixtures/stderr.bin",
            "files": {"output": "fixtures/stdout.bin"}}})
        command = (shutil.which("node"), "{test}", "{arguments}")
        result = self.validate(baseline_command=command, migration_command=command)
        self.assertEqual(result["summary"]["verdict"], "PASS", result)


if __name__ == "__main__":
    unittest.main()
