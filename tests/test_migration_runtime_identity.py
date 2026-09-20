"""Executable provenance and capture-identity regression tests."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from test_migration_captured_execution import runner


class RuntimeIdentityTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="migration-identities-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.project = self.root / "project"
        self.project.mkdir()
        # Explicit trusted wrapper; hash is for this file, not for its interpreter.
        self.runtime = self.root / "runtime"
        self.runtime.write_text(f"#!/bin/sh\nexec {shlex.quote(sys.executable)} \"$@\"\n")
        self.runtime.chmod(0o700)
        self.source = self.project / "case.test.js"
        self.source.write_text("print('ok')\n")

    def validate(self, **kwargs):
        options = {"baseline_command": [str(self.runtime), "{test}"],
                   "migration_command": [str(self.runtime), "{test}"],
                   "timeout_seconds": 2, "total_timeout_seconds": 10}
        options.update(kwargs)
        return runner.validate_project(self.project, **options)

    def test_complete_measurement_binds_the_actual_selected_file_bytes(self):
        report = self.validate()
        self.assertEqual(report["summary"]["verdict"], "PASS", report)
        identities = report["runtime_identities"]
        self.assertEqual(identities["baseline"], identities["migration"])
        self.assertEqual(identities["baseline"]["sha256"], hashlib.sha256(self.runtime.read_bytes()).hexdigest())
        self.assertEqual(identities["baseline"]["executable"], str(self.runtime))
        self.assertEqual(identities["baseline"]["mode"], 0o700)
        self.assertEqual(identities["baseline"]["bytes"], self.runtime.stat().st_size)
        self.assertTrue(report["runtime_identity_rechecked"])
        self.assertEqual(report["runtime_identity_scope"], "executable-bytes-before-and-after-suite")
        self.assertFalse(report["release_certification"])
        self.assertEqual(json.loads(json.dumps(report)), report)

    def test_live_runtime_modification_cannot_award_pass_even_when_both_outputs_match(self):
        # Both legs exit zero and print identical bytes, but change their trusted
        # wrapper. No subprocess or filesystem mocks participate in this test.
        self.source.write_text(f"from pathlib import Path\np=Path({str(self.runtime)!r})\np.write_text(p.read_text()+'# changed\\n')\nprint('same')\n")
        report = self.validate()
        self.assertEqual(report["summary"]["verdict"], "ERROR", report)
        self.assertFalse(report["runtime_identity_rechecked"])
        self.assertEqual(report["summary"]["passed"], 1)  # keep process evidence
        row = report["validation_results"][0]
        self.assertEqual(row["baseline"]["exit_code"], 0)
        self.assertEqual(row["baseline"]["streams"], row["migration"]["streams"])
        self.assertTrue(any("changed during validation" in error["message"] for error in report["errors"]))

    def test_identity_is_rechecked_after_a_runtime_execution_error(self):
        calls = []
        real = runner.measure_runtime_identities
        def tracked(commands, deadline):
            calls.append(commands)
            return real(commands, deadline)
        with patch.object(runner, "measure_runtime_identities", side_effect=tracked), \
             patch.object(runner, "run_command", side_effect=OSError("injected launch failure")):
            report = self.validate()
        self.assertEqual(len(calls), 2)
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertTrue(report["runtime_identity_rechecked"])
        self.assertTrue(any("injected launch failure" in error["message"] for error in report["errors"]))

    def test_identity_recheck_failure_does_not_erase_completed_process_observations(self):
        real = runner.measure_runtime_identities
        count = 0
        def failing(commands, deadline):
            nonlocal count
            count += 1
            if count == 2:
                raise FileNotFoundError("runtime vanished")
            return real(commands, deadline)
        with patch.object(runner, "measure_runtime_identities", side_effect=failing):
            report = self.validate()
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertFalse(report["runtime_identity_rechecked"])
        self.assertEqual(report["validation_results"][0]["baseline"]["exit_code"], 0)
        self.assertEqual(report["validation_results"][0]["migration"]["exit_code"], 0)

    def test_expired_identity_deadline_is_an_error_not_a_partial_digest(self):
        with self.assertRaises(TimeoutError):
            runner.runtime_identity(str(self.runtime), time.monotonic() - 1)

    def test_oversized_executable_is_rejected_before_reading_contents(self):
        with self.runtime.open("wb") as file:
            file.truncate(runner.MAX_EXECUTABLE_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "512 MiB"):
            runner.runtime_identity(str(self.runtime), time.monotonic() + 2)

    def test_nonregular_nonexecutable_and_symlink_identity_inputs_are_refused(self):
        fifo = self.root / "pipe"
        os.mkfifo(fifo)
        fifo.chmod(0o700)
        with self.assertRaises(ValueError):
            runner.runtime_identity(str(fifo), time.monotonic() + 2)
        self.runtime.chmod(0o600)
        with self.assertRaises(ValueError):
            runner.runtime_identity(str(self.runtime), time.monotonic() + 2)
        alias = self.root / "alias"
        alias.symlink_to("runtime")
        with self.assertRaises(OSError):
            runner.runtime_identity(str(alias), time.monotonic() + 2)
        with self.assertRaises(ValueError):
            runner.runtime_identity("relative", time.monotonic() + 2)

    def test_runtime_inside_either_project_is_refused_before_launch(self):
        internal = self.project / "runtime"
        internal.write_bytes(self.runtime.read_bytes())
        internal.chmod(0o700)
        with patch.object(runner, "run_command", side_effect=AssertionError("must not launch")):
            report = self.validate(migration_command=[str(internal), "{test}"])
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertEqual(report["validation_results"], [])
        self.assertIn("outside both", report["errors"][0]["message"])

    def test_nested_input_roots_are_rejected_before_capture(self):
        nested = self.project / "candidate"
        nested.mkdir()
        with patch.object(runner, "capture_project", side_effect=AssertionError("must not capture")):
            report = self.validate(migrated_project=nested)
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertIn("must not be nested", report["errors"][0]["message"])

    def test_hardlinked_input_is_refused_instead_of_flattening_alias_semantics(self):
        first = self.project / "first"
        first.write_text("input")
        os.link(first, self.project / "second")
        with patch.object(runner, "run_command", side_effect=AssertionError("must not launch")):
            report = self.validate()
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertIn("hard-linked", report["errors"][0]["message"])
        self.assertEqual(report["validation_results"], [])

    def test_metadata_change_between_lstat_and_open_fails_before_capture(self):
        real_open = os.open
        changed = False
        def race(path, flags, *args, **kwargs):
            nonlocal changed
            if Path(path) == self.source and not changed:
                changed = True
                self.source.chmod(0o777)
            return real_open(path, flags, *args, **kwargs)
        with patch.object(runner.os, "open", side_effect=race):
            report = self.validate()
        self.assertTrue(changed)
        self.assertEqual(report["summary"]["verdict"], "ERROR")
        self.assertIn("changed before capture", report["errors"][0]["message"])

    def test_duplicate_roles_hash_one_file_once_per_phase_not_as_independent_evidence(self):
        real = runner.runtime_identity
        with patch.object(runner, "runtime_identity", wraps=real) as measured:
            report = self.validate()
        self.assertEqual(report["summary"]["verdict"], "PASS")
        self.assertEqual(measured.call_count, 2)

    def test_failed_and_timed_out_workloads_keep_their_nonpassing_verdict(self):
        for source in ["raise SystemExit(7)\n", "import time\ntime.sleep(30)\n"]:
            self.source.write_text(source)
            report = self.validate(timeout_seconds=0.1)
            self.assertEqual(report["summary"]["verdict"], "FAIL", report)
            self.assertTrue(report["runtime_identity_rechecked"])


if __name__ == "__main__":
    unittest.main()
