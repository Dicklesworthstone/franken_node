"""Full captured-source/stdin reduction through production capture and replay.

These explicit Node/Node cases test the migration workflow, not native Franken
compatibility. Runtime, environment, transport, and oracle admission stay live.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import failure_replay as replay
import minimize_migration_failure as minimizer


@unittest.skipUnless(os.name == "posix" and shutil.which("node"), "real Node and POSIX required")
class CapturedReductionTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="captured-reduction-")
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.before, self.after = self.root / "before", self.root / "after"
        self.before.mkdir()
        self.after.mkdir()
        self.command = [shutil.which("node"), "{test}", "{arguments}"]

    def capture(self):
        return replay.capture_migration(self.before, migrated_project=self.after,
            baseline_command=self.command, migration_command=self.command,
            timeout_seconds=3, total_timeout_seconds=30)

    def minimize(self, artifact, **kwargs):
        return minimizer.minimize_migration(artifact, execute=True,
            baseline_command=self.command, migration_command=self.command,
            seconds=90, max_executions=kwargs.pop("max_executions", 512), **kwargs)

    def seed_input(self, *, mode="pipe", protected=False):
        for project, output in ((self.before, "reference"), (self.after, "candidate")):
            (project / "fixtures").mkdir()
            (project / "fixtures/request.bin").write_bytes(b"noise\0\xfftrailer")
            (project / "fixtures/unselected.bin").write_bytes(b"do not modify")
            (project / "app.test.cjs").write_text(
                "const b=require('fs').readFileSync(0);"
                f"console.log(b.includes(255)?{json.dumps(output)}:'no trigger');")
            # A previously passing case requires the NUL byte to survive too.
            (project / "guard.test.cjs").write_text(
                "const b=require('fs').readFileSync(0);console.log(b.includes(0)?'guard-kept':'guard-changed');")
            tests = ["app.test.cjs", "guard.test.cjs"]
            manifest = {"schema_version": replay.runner.MIGRATION_TEST_SCHEMA, "tests": tests,
                "max_concurrent_tests": 2,
                "execution": {name: {"stdin": "fixtures/request.bin", "stdin_mode": mode} for name in tests}}
            if protected:
                manifest["expectations"] = {"guard.test.cjs": {"stdout": "fixtures/request.bin"}}
            (project / ".franken-node").mkdir()
            (project / replay.runner.MIGRATION_TEST_MANIFEST).write_text(json.dumps(manifest))

    def test_minified_source_reduces_through_capsule_and_replays(self):
        for project, value in ((self.before, "reference"), (self.after, "candidate")):
            (project / "app.test.cjs").write_text(
                f"const unused=123;console.log({json.dumps(value)});const other=456;")
        artifact = self.capture()
        previous = copy.deepcopy(artifact)
        # This checks the bounded capture/reduce/replay path, not a completed
        # character-level minimum. Keep enough search for an accepted deletion
        # while exercising the same reserved final-confirmation budget.
        reduced = self.minimize(artifact, source_granularity="utf8", max_executions=32)
        self.assertEqual(artifact, previous)
        self.assertTrue(reduced["minimized"])
        self.assertEqual(reduced["minimization"]["source_granularity"], "utf8")
        self.assertEqual(len(reduced["minimization"]["reduction_kernel_sha256"]), 64)
        self.assertLessEqual(reduced["minimization"]["stats"]["executions"], 32)
        self.assertEqual(reduced["minimization"]["final_confirmations"], 2)
        self.assertEqual(minimizer.behavior(reduced["expected"]), minimizer.behavior(artifact["expected"]))
        result = replay.replay_migration(reduced, execute=True,
            baseline_command=self.command, migration_command=self.command)
        self.assertEqual(result["verdict"], "REPRODUCED", result)
        self.assertEqual(result["observed_validation_verdict"], "FAIL")

    def test_binary_stdin_reduction_preserves_all_cases_and_sources(self):
        self.seed_input()
        artifact = self.capture()
        original = copy.deepcopy(artifact)
        result = self.minimize(artifact, stdin_files=["fixtures/request.bin"])
        self.assertEqual(artifact, original)
        self.assertTrue(result["minimized"])
        self.assertEqual(result["minimization"]["source_files"], [])
        self.assertEqual(result["minimization"]["stdin_files"], ["fixtures/request.bin"])
        self.assertFalse(result["minimization"]["global_minimum_claimed"])
        before, after = replay.validate_capsule(artifact), replay.validate_capsule(result)
        for leg in replay.LEGS:
            old = {entry.path: entry for entry in before[leg]}
            new = {entry.path: entry for entry in after[leg]}
            self.assertEqual(new["fixtures/request.bin"].data, b"\0\xff")
            for name in old.keys() - {"fixtures/request.bin"}:
                self.assertEqual(new[name], old[name])
        self.assertEqual(result["expected"]["cases"], artifact["expected"]["cases"])
        self.assertEqual(len(result["expected"]["cases"]), 2)
        self.assertTrue(any(case["status"] == "PASS" for case in result["expected"]["cases"]))
        self.assertTrue(all(attempt["leg"] == "both" and attempt["kind"] == "stdin"
                            for attempt in result["minimization"]["attempts"]))
        self.assertEqual((self.before / "fixtures/request.bin").read_bytes(), b"noise\0\xfftrailer")

    def test_file_mode_input_reduces_and_replays_after_original_moves(self):
        self.seed_input(mode="file")
        result = self.minimize(self.capture(), stdin_files=["fixtures/request.bin"])
        self.before.rename(self.root / "original-before-unavailable")
        self.after.rename(self.root / "original-after-unavailable")
        outcome = replay.replay_migration(result, execute=True,
            baseline_command=self.command, migration_command=self.command)
        self.assertEqual(outcome["verdict"], "REPRODUCED", outcome)
        inventories = {leg: replay.runner.captured_test_inventory(entries)
                       for leg, entries in replay.validate_capsule(result).items()}
        self.assertTrue(all(settings.stdin_mode == "file" for settings in inventories["baseline"].values()))

    def test_output_fixture_cannot_be_reduced_even_for_another_case(self):
        self.seed_input(protected=True)
        artifact = self.capture()
        with mock.patch.object(replay, "runtime_bindings") as resolve:
            with self.assertRaisesRegex(ValueError, "output expectation fixture"):
                self.minimize(artifact, stdin_files=["fixtures/request.bin"])
        resolve.assert_not_called()

    def test_undeclared_stdin_and_duplicate_or_empty_selections_are_rejected(self):
        self.seed_input()
        artifact = self.capture()
        for paths in ([], ["fixtures/unselected.bin"], ["../request.bin"],
                      ["fixtures/request.bin", "fixtures/request.bin"], "fixtures/request.bin"):
            with self.subTest(paths=paths), mock.patch.object(replay, "runtime_bindings") as resolve:
                with self.assertRaises(ValueError):
                    self.minimize(artifact, stdin_files=paths)
                resolve.assert_not_called()

    def test_source_and_stdin_selection_cannot_overlap(self):
        self.seed_input()
        artifact = self.capture()
        with mock.patch.object(replay, "runtime_bindings") as resolve:
            with self.assertRaisesRegex(ValueError, "disjoint"):
                self.minimize(artifact, source_files=["app.test.cjs"], stdin_files=["app.test.cjs"])
        resolve.assert_not_called()

    def test_exhaustion_keeps_original_and_reserves_fresh_final_confirmations(self):
        self.seed_input()
        artifact = self.capture()
        result = self.minimize(artifact, stdin_files=["fixtures/request.bin"], max_executions=4)
        self.assertFalse(result["minimized"])
        self.assertEqual(result["expected"], artifact["expected"])
        self.assertEqual(result["minimization"]["stats"]["executions"], 4)
        self.assertEqual(result["minimization"]["final_confirmations"], 2)
        self.assertEqual(result["minimization"]["budget_exhausted"], "execution_budget")
        self.assertFalse(result["minimization"]["search_complete"])

    def test_invalid_granularity_is_rejected_before_capsule_or_runtime_access(self):
        with mock.patch.object(replay, "validate_capsule") as read:
            with self.assertRaisesRegex(ValueError, "source granularity"):
                self.minimize({}, source_granularity="unchecked-parser")
        read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
