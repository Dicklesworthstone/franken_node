"""Captured stdin transport is observable input, not an interchangeable pipe.

Real Python and Node processes exercise the standalone runner. These tests do
not certify native-engine parity, ambient-effect replay, or hostile-code isolation.
"""
from __future__ import annotations

import copy
import errno
import fcntl
import hashlib
import json
import os
import shutil
import signal
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import migration_validation_runner as runner

COMMAND = (sys.executable, "-S", "{test}", "{arguments}")
PAYLOAD = b"\x00\xffrequest\r\nseek-again"


class StdinTransportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="migration-stdin-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.project = self.root / "project"
        self.project.mkdir()
        (self.project / ".franken-node").mkdir()
        (self.project / "input.bin").write_bytes(PAYLOAD)

    def setup(self, source, *, mode="file", supplied=True, count=1):
        tests = [f"case-{i}.cjs" for i in range(count)]
        manifest = {"schema_version": runner.MIGRATION_TEST_SCHEMA, "tests": tests,
                    "max_concurrent_tests": min(count, 4), "execution": {}}
        for test in tests:
            (self.project / test).write_text(source, encoding="utf-8")
            settings = {}
            if supplied:
                settings["stdin"] = "input.bin"
            if mode is not None:
                settings["stdin_mode"] = mode
            manifest["execution"][test] = settings
        self.write_manifest(manifest)
        return manifest

    def write_manifest(self, manifest):
        (self.project / runner.MIGRATION_TEST_MANIFEST).write_text(json.dumps(manifest))

    def validate(self, **kwargs):
        return runner.validate_project(self.project,
            baseline_command=kwargs.pop("baseline_command", COMMAND),
            migration_command=kwargs.pop("migration_command", COMMAND),
            timeout_seconds=kwargs.pop("timeout_seconds", 3),
            total_timeout_seconds=kwargs.pop("total_timeout_seconds", 15), **kwargs)

    def assert_pass(self, report, transport):
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        for row in report["validation_results"]:
            for leg in ("baseline", "migration"):
                self.assertEqual(row[leg]["stdin_transport"], transport)
                self.assertTrue(row[leg]["streams"]["stdout"]["complete"])

    def test_real_file_stdin_is_seekable_read_only_and_unlinked_before_execution(self):
        self.setup("import os, fcntl, stat\n"
            "m = os.fstat(0)\nassert stat.S_ISREG(m.st_mode) and m.st_nlink == 0\n"
            "assert fcntl.fcntl(0, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY\n"
            "assert os.lseek(0, 0, os.SEEK_CUR) == 0\n"
            f"assert os.read(0, 1000) == {PAYLOAD!r}\n"
            "os.lseek(0, 0, os.SEEK_SET)\n"
            f"assert os.read(0, 1000) == {PAYLOAD!r}\nprint('seek verified')\n")
        report = self.validate(compare_filesystem=True)
        self.assert_pass(report, "file")
        self.assertEqual((self.project / "input.bin").read_bytes(), PAYLOAD)
        for leg in ("baseline", "migration"):
            self.assertEqual(report["validation_results"][0][leg]["workspace_delta"]["changed_paths"], 0)

    def test_explicit_pipe_and_legacy_omission_preserve_fifo_semantics(self):
        for mode in ["pipe", None]:
            with self.subTest(mode=mode):
                self.setup("import os, stat, sys\nassert stat.S_ISFIFO(os.fstat(0).st_mode)\n"
                           f"assert sys.stdin.buffer.read() == {PAYLOAD!r}\nprint('pipe verified')\n", mode=mode)
                self.assert_pass(self.validate(), "pipe")

    def test_no_fixture_remains_devnull_for_legacy_omission_and_explicit_file(self):
        for mode in [None, "file"]:
            with self.subTest(mode=mode):
                self.setup("import os, stat\nassert stat.S_ISCHR(os.fstat(0).st_mode)\n"
                           "assert os.read(0, 1) == b''\nprint('no input')\n", mode=mode, supplied=False)
                self.assert_pass(self.validate(), "none")

    def test_empty_fixtures_preserve_the_selected_transport(self):
        (self.project / "input.bin").write_bytes(b"")
        for mode in ["file", "pipe"]:
            predicate = "S_ISREG" if mode == "file" else "S_ISFIFO"
            with self.subTest(mode=mode):
                self.setup(f"import os, stat\nassert stat.{predicate}(os.fstat(0).st_mode)\n"
                           "assert os.read(0, 1) == b''\nprint('empty')\n", mode=mode)
                self.assert_pass(self.validate(), mode)

    def test_invalid_modes_and_explicit_pipe_without_fixture_never_launch(self):
        for value in [None, True, False, 1, [], {}, "FILE", "socket", "secret-invalid-mode"]:
            manifest = self.setup("print('must not execute')\n")
            manifest["execution"]["case-0.cjs"]["stdin_mode"] = value
            self.write_manifest(manifest)
            with self.subTest(value=value), mock.patch.object(runner, "run_command") as launch:
                report = self.validate()
                launch.assert_not_called()
                self.assertEqual(report["summary"]["verdict"], "ERROR")
                self.assertNotIn("secret-invalid-mode", json.dumps(report))
        self.setup("print('must not execute')\n", mode="pipe", supplied=False)
        with mock.patch.object(runner, "run_command") as launch:
            report = self.validate()
        launch.assert_not_called()
        self.assertEqual(report["summary"]["verdict"], "ERROR")

    def test_changed_candidate_transport_is_rejected_before_both_legs(self):
        self.setup("print('must not execute')\n", mode="file")
        candidate = self.root / "candidate"
        shutil.copytree(self.project, candidate)
        path = candidate / runner.MIGRATION_TEST_MANIFEST
        manifest = json.loads(path.read_text())
        manifest["execution"]["case-0.cjs"]["stdin_mode"] = "pipe"
        path.write_text(json.dumps(manifest))
        with mock.patch.object(runner, "run_command") as launch:
            report = self.validate(migrated_project=candidate)
        launch.assert_not_called()
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertIn("settings differ", report["errors"][0]["message"])

    def test_file_input_comes_from_immutable_capture_not_staged_fixture(self):
        self.setup("import pathlib, sys\n"
                   "assert pathlib.Path('input.bin').read_bytes() == b'changed after capture'\n"
                   f"assert sys.stdin.buffer.read() == {PAYLOAD!r}\nprint('captured')\n")
        original = runner.stage_project
        def changed(entries, workspace, deadline, **kwargs):
            original(entries, workspace, deadline, **kwargs)
            (workspace / "input.bin").write_bytes(b"changed after capture")
        with mock.patch.object(runner, "stage_project", side_effect=changed):
            self.assert_pass(self.validate(), "file")

    def test_concurrent_legs_each_start_with_a_fresh_cursor_and_cannot_write_input(self):
        self.setup("import os, errno\n"
            f"assert os.read(0, 4) == {PAYLOAD[:4]!r}\n"
            "try:\n os.write(0, b'changed')\nexcept OSError as e:\n assert e.errno == errno.EBADF\n"
            "else:\n raise AssertionError('input was writable')\n"
            "os.lseek(0, 0, os.SEEK_SET)\n"
            f"assert os.read(0, 1000) == {PAYLOAD!r}\nprint('independent')\n", count=8)
        report = self.validate()
        self.assert_pass(report, "file")
        self.assertEqual(report["summary"]["passed"], 8)

    @unittest.skipUnless(shutil.which("node"), "real Node executable unavailable")
    def test_real_node_receives_regular_and_pipe_stdin_without_byte_changes(self):
        for mode in ["file", "pipe"]:
            method = "isFile" if mode == "file" else "isFIFO"
            self.setup("const fs = require('node:fs');\n"
                f"if (!fs.fstatSync(0).{method}()) throw Error('wrong transport');\n"
                f"if (fs.readFileSync(0).toString('hex') !== '{PAYLOAD.hex()}') throw Error('wrong bytes');\n"
                "console.log('node stdin verified');\n", mode=mode)
            command = (shutil.which("node"), "{test}", "{arguments}")
            self.assert_pass(self.validate(baseline_command=command, migration_command=command), mode)

    def test_portable_reexecution_restores_file_input_after_original_is_unavailable(self):
        self.setup("import os, stat\nassert stat.S_ISREG(os.fstat(0).st_mode)\n"
            f"assert os.read(0, 1000) == {PAYLOAD!r}\nprint('replayed input')\n", count=3)
        path = self.root / "capture.fnmigration"
        report = self.validate(bundle_path=path)
        self.assert_pass(report, "file")
        digest = report["replay_bundle"]["sha256"]
        self.project.rename(self.root / "original-unavailable")
        replay = runner.replay_captured_bundle(path, expected_sha256=digest,
                    baseline_command=COMMAND, migration_command=COMMAND)
        self.assertEqual(replay["replay_outcome"], "REPRODUCED", replay)
        self.assert_pass(replay["execution"], "file")
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_forged_or_missing_file_transport_evidence_is_rejected(self):
        self.setup("print('ok')\n")
        path = self.root / "capture.fnmigration"
        self.assert_pass(self.validate(bundle_path=path), "file")
        bundle = runner.read_replay_bundle(path)
        for mode in [None, "none", "pipe", True, {}, "file-forged"]:
            manifest = copy.deepcopy(bundle.manifest)
            manifest["report"]["validation_results"][0]["baseline"]["stdin_transport"] = mode
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                runner._validate_bundle_manifest(manifest, bundle.objects)
        manifest = copy.deepcopy(bundle.manifest)
        del manifest["report"]["validation_results"][0]["baseline"]["stdin_transport"]
        with self.assertRaises(ValueError):
            runner._validate_bundle_manifest(manifest, bundle.objects)

    def test_historical_pipe_evidence_without_transport_metadata_stays_valid(self):
        self.setup("import os, stat\nassert stat.S_ISFIFO(os.fstat(0).st_mode)\nprint('pipe')\n", mode=None)
        path = self.root / "capture.fnmigration"
        report = self.validate(bundle_path=path)
        bundle = runner.read_replay_bundle(path)
        manifest = copy.deepcopy(bundle.manifest)
        for row in manifest["report"]["validation_results"]:
            for role in ("baseline", "migration"):
                del row[role]["stdin_transport"]
        runner._validate_bundle_manifest(manifest, bundle.objects)
        self.assertEqual(runner._observation_projection(manifest["report"]),
                         runner._observation_projection(report))
        self.assertEqual(runner.captured_test_inventory(bundle.snapshots["baseline"])["case-0.cjs"].stdin_mode,
                         "pipe")

    def test_owned_stdin_fd_closes_on_normal_return_and_launch_error(self):
        descriptors = []
        original = runner._stdin_source
        from contextlib import contextmanager
        @contextmanager
        def observed(*args):
            with original(*args) as fd:
                descriptors.append(fd)
                yield fd
        with mock.patch.object(runner, "_stdin_source", observed):
            outcome = runner.run_command([sys.executable, "-S", "-c", "print('ok')"], self.project,
                timeout=2, max_output_bytes=1024, environment=dict(os.environ),
                input_bytes=PAYLOAD, stdin_mode="file")
            self.assertEqual(outcome["exit_code"], 0)
            for fd in descriptors:
                with self.assertRaises(OSError) as error:
                    os.fstat(fd)
                self.assertEqual(error.exception.errno, errno.EBADF)
            with mock.patch.object(runner.subprocess, "Popen", side_effect=OSError("launch failed")):
                with self.assertRaises(OSError):
                    runner.run_command([sys.executable], self.project, timeout=2, max_output_bytes=1024,
                        environment=dict(os.environ), input_bytes=PAYLOAD, stdin_mode="file")
        with self.assertRaises(OSError):
            os.fstat(descriptors[-1])

    def test_cancelled_or_expired_preparation_never_launches(self):
        cancellation = runner.CancellationState(signal.SIGTERM)
        with mock.patch.object(runner.subprocess, "Popen") as launch:
            with self.assertRaises(runner.ExecutionCancelled):
                runner.run_command([sys.executable], self.project, timeout=2, max_output_bytes=1024,
                    environment={}, input_bytes=PAYLOAD, stdin_mode="file", cancellation=cancellation)
            with self.assertRaises(TimeoutError):
                runner.run_command([sys.executable], self.project, timeout=-1, max_output_bytes=1024,
                    environment={}, input_bytes=PAYLOAD, stdin_mode="file")
        launch.assert_not_called()

    def test_file_mode_does_not_disable_timeout_or_output_limits(self):
        for source, reason in [("import time\ntime.sleep(2)\n", "timeout"),
                               ("print('x' * 5000)\n", "output_limit")]:
            with self.subTest(reason=reason):
                self.setup(source)
                report = self.validate(timeout_seconds=0.5, max_output_bytes=100)
                self.assertEqual(report["summary"]["verdict"], "FAIL", report)
                for role in ("baseline", "migration"):
                    capture = report["validation_results"][0][role]
                    self.assertEqual(capture["termination"], reason)
                    self.assertFalse(capture["streams"]["stdout"]["complete"])
                    self.assertEqual(capture["stdin_transport"], "file")

    def test_library_modes_are_validated_before_any_process(self):
        with mock.patch.object(runner.subprocess, "Popen") as launch:
            for mode in [None, True, [], {}, "unrecognized"]:
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    runner.run_command([sys.executable], self.project, timeout=1, max_output_bytes=100,
                        environment={}, input_bytes=PAYLOAD, stdin_mode=mode)
        launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
